package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode"

	"github.com/lrstanley/girc"
)

// TODO: Detect PING timeout and quit (suspend laptop to reproduce this)
// TODO: Disable girc tracking to sparse some memory

var ircPath string

const (
	logfn  = "log"
	nickfn = "usr"
	outfn  = "out"
	infn   = "in"
	idfn   = "id"
)

const masterChan = ""

type ircChan struct {
	done   chan bool
	nickfp string
	ln     net.Listener
}

type ircDir struct {
	done chan bool
	infp string
	ch   *ircChan
}

var ircDirs = make(map[string]*ircDir)

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
	debug      bool
)

var (
	mntRegex *regexp.Regexp
	logFile  *os.File
)

var channelCmds = map[string]int{
	girc.JOIN:      0,
	girc.PART:      0,
	girc.KICK:      0,
	girc.MODE:      0,
	girc.TOPIC:     0,
	girc.NAMES:     0,
	girc.LIST:      0,
	girc.RPL_TOPIC: 1,
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

func cleanup() {
	for name, _ := range ircDirs {
		err := removeListener(name)
		if err != nil {
			log.Printf("Couldn't remove %q: %s\n", name, err)
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
	flag.StringVar(&name, "f", user.Username, "real name")
	flag.StringVar(&prefix, "i", filepath.Join(user.HomeDir, "irc"), "directory path")
	flag.StringVar(&nick, "n", user.Username, "nick")
	flag.IntVar(&port, "p", 6667, "TCP port")
	flag.BoolVar(&useTLS, "t", false, "use TLS")
	flag.BoolVar(&debug, "d", false, "enable debug output")

	flag.Usage = usage
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
			return nil, err
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
			return '_'
		}
	}

	return strings.Map(mfunc, name)
}

// Like os.OpenFile but for FIFOs.
func openFifo(name string, flag int, perm os.FileMode) (*os.File, error) {
	fi, err := os.Lstat(name)
	if os.IsNotExist(err) {
		err = syscall.Mkfifo(name, syscall.S_IFIFO|uint32(perm))
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("%q is not a named pipe", name)
	}

	fifo, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}

	return fifo, err
}

// Like ioutil.Write but doesn't truncate and appends instead.
func appendFile(filename string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
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

func isMention(client *girc.Client, event *girc.Event) bool {
	return event.IsFromUser() &&
		event.Source.Name != client.GetNick() ||
		mntRegex.MatchString(event.Trailing)
}

func getCmdChan(event *girc.Event) (string, bool) {
	idx, ok := channelCmds[event.Command]
	if !ok || len(event.Params) < idx+1 {
		return "", false
	}

	chanName := event.Params[idx]
	if girc.IsValidChannel(chanName) {
		return chanName, true
	}

	return "", false
}

func getSourceDirs(client *girc.Client, event *girc.Event) ([]*string, error) {
	var names []*string

	user := client.LookupUser(event.Source.Name)
	if user == nil {
		return names, fmt.Errorf("user %q doesn't exist", event.Source.Name)
	}

	for name, dir := range ircDirs {
		if dir.ch != nil && user.InChannel(name) {
			names = append(names, &name)
		}
	}

	return names, nil
}

func getEventDirs(client *girc.Client, event *girc.Event) ([]*string, error) {
	if event.Command == girc.QUIT || event.Command == girc.NICK {
		return getSourceDirs(client, event)
	}

	name := masterChan
	if event.IsFromChannel() {
		name = event.Params[0]
	} else if event.IsFromUser() {
		name = event.Source.Name
		if name == client.GetNick() {
			name = event.Params[0]
		}

		// TODO: Do this in handleMsg
		err := createListener(client, name)
		if err != nil {
			return []*string{}, err
		}
	} else {
		channel, isChanCmd := getCmdChan(event)
		if isChanCmd {
			name = channel
		}
	}

	return []*string{&name}, nil
}

func storeName(dir, name string) error {
	idfp := filepath.Join(dir, idfn)
	file, err := os.OpenFile(idfp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0200)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	_, err = file.WriteString(name + "\n")
	if err != nil {
		os.Remove(idfp)
		return err
	}

	err = file.Chmod(0400)
	if err != nil {
		os.Remove(idfp)
		return err
	}

	return nil
}

func createListener(client *girc.Client, name string) error {
	_, ok := ircDirs[name]
	if ok {
		return nil
	}

	dir := filepath.Join(ircPath, normalize(name))
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}
	if name != masterChan {
		err = storeName(dir, name)
		if err != nil {
			return err
		}
	}

	idir := &ircDir{
		make(chan bool, 1),
		filepath.Join(dir, infn),
		nil,
	}
	ircDirs[name] = idir

	go recvInput(client, name, idir)
	if girc.IsValidChannel(name) {
		ch := &ircChan{
			make(chan bool, 1),
			filepath.Join(dir, nickfn),
			nil,
		}

		idir.ch = ch
		go serveNicks(client, name, ch)
	}

	return nil
}

func removeListener(name string) error {
	dir, ok := ircDirs[name]
	if !ok {
		return fmt.Errorf("no directory exists for %q", name)
	}
	defer delete(ircDirs, name)

	// hack to gracefully terminate the recvInput goroutine
	dir.done <- true
	fifo, err := openFifo(dir.infp, os.O_WRONLY|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	fifo.Close()

	ch := dir.ch
	if ch != nil {
		ch.done <- true
		err := ch.ln.Close()
		if err != nil {
			return err
		}
	}

	return os.Remove(dir.infp)
}

func handleInput(client *girc.Client, name, input string) error {
	if input == "" {
		return nil
	} else if input[0] != '/' {
		input = fmt.Sprintf("/%s %s :%s", girc.PRIVMSG, name, input)
	}

	if len(input) <= 1 {
		return nil
	}

	input = input[1:]
	if strings.HasPrefix(input, girc.PRIVMSG) {
		source := client.GetNick()

		event := girc.ParseEvent(fmt.Sprintf(":%s %s", source, input))
		if event == nil {
			return nil
		}

		client.RunHandlers(event)
	}

	return client.Cmd.SendRaw(input + "\r\n")
}

func recvInput(client *girc.Client, name string, dir *ircDir) {
	for {
		fifo, err := openFifo(dir.infp, os.O_RDONLY, 0600)
		select {
		case <-dir.done:
			return
		default:
			if err != nil {
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
		}
	}
}

func serveNicks(client *girc.Client, name string, ch *ircChan) {
	var err error

	ch.ln, err = net.Listen("unix", ch.nickfp)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := ch.ln.Accept()
		select {
		case <-ch.done:
			return
		default:
			if err != nil {
				log.Println(err)
				continue
			}

			ch := client.LookupChannel(name)
			if ch != nil {
				users := strings.Join(ch.UserList, "\n")
				_, err = conn.Write([]byte(users + "\n"))
				if err != nil {
					log.Println(err)
				}
			}

			conn.Close()
		}
	}
}

func fmtEvent(event *girc.Event, strip bool) (string, bool) {
	out, ok := event.Pretty()
	if !ok {
		return "", false
	}

	if strip && (event.IsFromChannel() || event.IsFromUser()) {
		// Strip the user/channel name from the output string
		// since this information is already encoded in the path.

		prefix := fmt.Sprintf("[%s] ", event.Params[0])
		out = strings.TrimPrefix(out, prefix)
	}

	out = fmt.Sprintf("%v %s\n", event.Timestamp.Unix(), out)
	return out, true
}

func writeMention(event *girc.Event) error {
	out, ok := fmtEvent(event, false)
	if !ok {
		return nil
	}

	_, err := logFile.WriteString(out)
	if err != nil {
		return err
	}

	return nil
}

func writeEvent(event *girc.Event, name string) error {
	out, ok := fmtEvent(event, true)
	if !ok {
		return nil
	}

	dir := filepath.Join(ircPath, normalize(name))
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}

	outfp := filepath.Join(dir, outfn)
	return appendFile(outfp, []byte(out), 0600)
}

func handleJoin(client *girc.Client, event girc.Event) {
	if len(event.Params) < 1 || event.Source == nil {
		return
	}
	name := event.Params[0]

	if event.Source.Name == client.GetNick() {
		err := createListener(client, name)
		if err != nil {
			log.Printf("Couldn't join %q: %s\n", name, err)
			client.Cmd.Part(name)
		}
	}
}

func handlePart(client *girc.Client, event girc.Event) {
	if len(event.Params) < 1 || event.Source == nil {
		return
	}
	name := event.Params[0]

	if event.Source.Name == client.GetNick() {
		err := removeListener(name)
		if err != nil {
			log.Printf("Couldn't remove %q after part: %s\n", name, err)
		}
	}
}

func handleKick(client *girc.Client, event girc.Event) {
	if len(event.Params) < 2 || event.Params[1] != client.GetNick() {
		return
	}
	name := event.Params[0]

	err := removeListener(name)
	if err != nil {
		log.Printf("Couldn't remove %q after kick: %s\n", name, err)
	}
}

func handleMsg(client *girc.Client, event girc.Event) {
	if event.Source == nil {
		return
	} else if debug {
		fmt.Println(event.String())
	}

	// Proper handling for CTCPs is not implemented and will never
	// be implemented. Therefore we just ignore CTCPs except `/me`.
	isCtcp, ctcp := event.IsCTCP()
	if isCtcp && ctcp.Command != girc.CTCP_ACTION {
		return
	}

	switch event.Command {
	case girc.AWAY:
		return // Ignore, occurs too often.
	case girc.PRIVMSG:
		if isMention(client, &event) {
			err := writeMention(&event)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	names, err := getEventDirs(client, &event)
	if err != nil {
		log.Fatal(err)
	}

	for _, name := range names {
		err := writeEvent(&event, *name)
		if err != nil {
			log.Println(err)
		}
	}
}

func addHandlers(client *girc.Client) {
	client.Handlers.Add(girc.CONNECTED, func(c *girc.Client, e girc.Event) {
		err := createListener(c, masterChan)
		if err != nil {
			log.Fatalf("Couldn't create master channel: %s", err)
		}

		if flag.NArg() > 1 {
			channels := flag.Args()[1:]
			c.Cmd.Join(channels...)
		}
	})
	client.Handlers.Add(girc.DISCONNECTED, func(c *girc.Client, e girc.Event) {
		cleanup()
	})

	client.Handlers.Add(girc.JOIN, handleJoin)
	client.Handlers.Add(girc.PART, handlePart)
	client.Handlers.Add(girc.KICK, handleKick)

	client.Handlers.Add(girc.ALL_EVENTS, handleMsg)
}

func newClient() (*girc.Client, error) {
	var err error
	var tlsconf *tls.Config
	if useTLS {
		tlsconf, err = getTLSconfig()
		if err != nil {
			return nil, err
		}
	}

	config := girc.Config{
		Server:    server,
		Port:      port,
		Nick:      nick,
		User:      name,
		SSL:       useTLS,
		TLSConfig: tlsconf,
	}

	client := girc.New(config)
	addHandlers(client)

	return client, nil
}

func initDir() error {
	ircPath = filepath.Join(prefix, server)
	err := os.MkdirAll(ircPath, 0700)
	if err != nil {
		return err
	}

	logFp := filepath.Join(ircPath, logfn)
	logFile, err = os.OpenFile(logFp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	log.SetFlags(log.Lshortfile)
	parseFlags()

	err := initDir()
	if err != nil {
		log.Fatal(err)
	}

	mntRegex = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(nick) + `\b`)
	client, err := newClient()
	if err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		<-sig
		cleanup()
		os.Exit(1)
	}()

	err = client.Connect()
	cleanup()
	if err != nil {
		log.Fatal(err)
	}
}
