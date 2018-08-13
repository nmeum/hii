package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/lrstanley/girc"
)

var ircPath string

const (
	outfn = "out"
	infn  = "in"
)

var channels = make(map[string]string)

var (
	server     string
	clientKey  string
	clientCert string
	certs      string
	name       string
	prefix     string
	nick       string
	port       int
	useTLS     bool
)

var channelCmds = map[string]bool{
	girc.JOIN:  true,
	girc.PART:  true,
	girc.KICK:  true,
	girc.MODE:  true,
	girc.TOPIC: true,
	girc.NAMES: true,
	girc.LIST:  true,
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		"USAGE: %s [FLAGS] SERVER [CHANNEL...]\n\n"+
			"The following flags are supported:\n\n", os.Args[0])
	flag.PrintDefaults()

	// Explicitly calling os.Exit here to be able to also use this
	// function when command-line arguments are missing. The Exit
	// status 2 is also used by flag.ExitOnError.
	os.Exit(2)
}

func cleanup(client *girc.Client) {
	for name, _ := range channels {
		err := removeChannel(client, name)
		if err != nil {
			log.Printf("Couldn't remove channel %q\n", name)
		}
	}
}

func parseFlags() {
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// Flags are declared in this function instead of declaring them
	// globally in order to properly utilize the os/user package.

	flag.StringVar(&clientKey, "k", "", "key for certFP")
	flag.StringVar(&clientCert, "c", "", "cert for certFP")
	flag.StringVar(&certs, "r", "", "root certificates")
	flag.StringVar(&name, "f", user.Name, "real name")
	flag.StringVar(&prefix, "i", filepath.Join(user.HomeDir, "irc"), "directory path")
	flag.StringVar(&nick, "n", user.Username, "nick")
	flag.IntVar(&port, "p", 6667, "TCP port")
	flag.BoolVar(&useTLS, "t", false, "use TLS")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(flag.CommandLine.Output(), "Missing server argument\n")
		usage()
	}
	server = flag.Arg(0)

	if (clientKey == "" && clientCert != "") || (clientKey != "" && clientCert == "") {
		log.Fatal("For using certFP a certificate and key need to be provided")
	}
	if (clientKey != "" || clientCert != "" || certs != "") && !useTLS {
		log.Fatal("Certificates given but TLS wasn't enabled")
	}
}

func getTLSconfig() (*tls.Config, error) {
	config := &tls.Config{ServerName: server}
	if certs != "" {
		data, err := ioutil.ReadFile(certs)
		if err != nil {
			return nil, err
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("couldn't parse certificate %q", certs)
		}

		config.RootCAs = pool
	}

	if clientCert != "" && clientKey != "" {
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			log.Fatal(err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}

// Briefly modeled after the channel_normalize_path ii function.
func normalize(name string) string {
	mfunc := func(r rune) rune {
		switch {
		case r == '.' || r == '#' || r == '&' ||
			r == '+' || r == '!' || r == '-':
			return r
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return unicode.ToLower(r)
		default:
			return -1
		}
	}

	return strings.Map(mfunc, name)
}

// Like os.OpenFile but for FIFOs.
func openFifo(name string, flag int, perm os.FileMode) (*os.File, error) {
	_, err := os.Stat(name)
	if os.IsNotExist(err) {
		err = syscall.Mkfifo(name, syscall.S_IFIFO|uint32(perm))
		if err != nil {
			return nil, err
		}
	} else {
		log.Printf("named pipe for channel %q already exists\n", name)
	}

	fifo, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}

	return fifo, err
}

// Like ioutil.Write but doesn't truncate and appends instead.
func appendFile(filename string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func runHandlers(client *girc.Client, cmd, tr string, params ...string) {
	clientSource := &girc.Source{
		client.GetNick(),
		client.GetIdent(),
		client.GetHost(),
	}

	client.RunHandlers(&girc.Event{
		Source:    clientSource,
		Timestamp: time.Now(),
		Command:   cmd,
		Params:    params,
		Trailing:  tr,
	})
}

func isChannelCmd(event *girc.Event) bool {
	_, ok := channelCmds[event.Command]
	if !ok {
		return false
	}

	return len(event.Params) >= 1 &&
		girc.IsValidChannel(event.Params[0])
}

func createChannel(client *girc.Client, name string) error {
	chanName := girc.ToRFC1459(name)
	_, ok := channels[chanName]
	if ok {
		return fmt.Errorf("already joined %q", name)
	}

	dir := filepath.Join(ircPath, normalize(name))
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}

	channels[chanName] = filepath.Join(dir, infn)
	go recvInput(client, chanName)

	return nil
}

func removeChannel(client *girc.Client, name string) error {
	chanName := girc.ToRFC1459(name)
	fp, ok := channels[chanName]
	if !ok {
		return fmt.Errorf("no directory exists for %q", name)
	}

	return os.Remove(fp)
}

func joinChannel(client *girc.Client, name string) error {
	if client.IsInChannel(name) {
		return fmt.Errorf("client already joined channel %q", name)
	} else if !girc.IsValidChannel(name) {
		return fmt.Errorf("%q is not a valid channel name", name)
	}

	return createChannel(client, name)
}

func handleInput(client *girc.Client, chanName, input string) error {
	cmd := client.Cmd
	if input == "" {
		return nil
	}

	if input[0] != '/' {
		// Make sure that our msg is also recorded in the `out` log.
		runHandlers(client, girc.PRIVMSG, input, chanName)

		cmd.Message(chanName, input)
		return nil
	}

	if len(input) >= 1 {
		return nil
	}
	input = input[1:]

	// TODO handle shortcut commands

	return cmd.SendRaw(input)
}

func recvInput(client *girc.Client, name string) {
	for {
		fp, ok := channels[name]
		if !ok {
			break
		}

		fifo, err := openFifo(fp, os.O_RDONLY, 0600)
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		scanner := bufio.NewScanner(fifo)
		for scanner.Scan() {
			err = handleInput(client, name, scanner.Text())
			if err != nil {
				log.Println(err)
			}
		}

		err = scanner.Err()
		if err != nil {
			log.Println(err)
		}

		fifo.Close()
		os.Remove(fp)
	}
}

func fmtEvent(event *girc.Event) (string, bool) {
	out, ok := event.Pretty()
	if !ok {
		return "", false
	}

	if len(event.Params) >= 1 && girc.IsValidChannel(event.Params[0]) {
		// Strip the channel from the output string since this
		// information is already encoded in the file path.

		prefix := fmt.Sprintf("[%s] ", event.Params[0])
		out = strings.TrimPrefix(out, prefix)
	}

	out = fmt.Sprintf("%v %s\n", event.Timestamp.Unix(), out)
	return out, true
}

func handlePart(client *girc.Client, event girc.Event) {
	name := event.Params[0]

	err := removeChannel(client, name)
	if err != nil {
		log.Printf("Couldn't remove channel %q\n", name)
	}
}

func handleMsg(client *girc.Client, event girc.Event) {
	if event.Source == nil {
		return
	}

	dir := ircPath
	if event.IsFromChannel() || isChannelCmd(&event) {
		dir = filepath.Join(dir, normalize(event.Params[0]))
	} else if event.IsFromUser() {
		name := event.Source.Name
		dir = filepath.Join(dir, normalize(name))

		// createChannel only creates a channel if it doesn't exist.
		createChannel(client, name)
	}

	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatal(err)
	}

	out, ok := fmtEvent(&event)
	if !ok {
		return
	}

	outfp := filepath.Join(dir, outfn)
	err = appendFile(outfp, []byte(out), 0600)
	if err != nil {
		log.Printf("Couldn't write to %q: %s\n", outfp, err)
	}
}

func addHandlers(client *girc.Client) {
	client.Handlers.Add(girc.PART, handlePart)
	client.Handlers.Add(girc.KICK, handlePart)
	client.Handlers.Add(girc.DISCONNECTED, func(c *girc.Client, e girc.Event) {
		cleanup(c)
	})

	client.Handlers.Add(girc.CONNECTED, func(c *girc.Client, e girc.Event) {
		err := createChannel(c, "")
		if err != nil {
			log.Fatal("Couldn't create master channel")
		}

		if flag.NArg() > 1 {
			channels := flag.Args()[1:]
			c.Cmd.Join(channels...)
		}
	})

	client.Handlers.Add(girc.JOIN, func(c *girc.Client, e girc.Event) {
		name := e.Params[0]

		err := joinChannel(c, name)
		if err != nil {
			log.Printf("Couldn't create channel %q: %s\n", name, err)
			c.Cmd.Part(name)
		}
	})

	client.Handlers.Add(girc.ALL_EVENTS, handleMsg)
}

func main() {
	log.SetFlags(log.Lshortfile)

	flag.Usage = usage
	parseFlags()

	ircPath = filepath.Join(prefix, server)
	err := os.MkdirAll(ircPath, 0700)
	if err != nil {
		log.Fatal(err)
	}

	var tlsconf *tls.Config
	if useTLS {
		tlsconf, err = getTLSconfig()
		if err != nil {
			log.Fatal(err)
		}
	}

	client := girc.New(girc.Config{
		Server:    server,
		Port:      port,
		Nick:      nick,
		User:      name,
		SSL:       useTLS,
		TLSConfig: tlsconf,
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		<-sig
		cleanup(client)
		os.Exit(1)
	}()

	addHandlers(client)
	err = client.Connect()
	if err != nil {
		log.Fatal(err)
	}
}
