package main

import (
	"bufio"
	"bytes"
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
	done chan bool
	ln   net.Listener
}

type ircDir struct {
	name string
	done chan bool
	fp   string
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
	errNotExist = fmt.Errorf("IRC directory doesn't exist")
	errExist    = fmt.Errorf("IRC directory already exists")
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
		"USAGE: %s [FLAGS] SERVER [TARGET...]\n\n"+
			"The following flags are supported:\n\n", os.Args[0])
	flag.PrintDefaults()

	// Explicitly calling os.Exit here to be able to also use this
	// function when command-line arguments are missing. The Exit
	// status 2 is also used by flag.ExitOnError.
	os.Exit(2)
}

func cleanup() {
	for _, dir := range ircDirs {
		err := removeListener(dir.name)
		if err != nil {
			log.Printf("Couldn't remove %q: %s\n", dir.name, err)
		}
	}
}

func die(err error) {
	cleanup()
	log.Fatal(err)
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
		case r == '#' || r == '&' || r == '+' ||
			r == '!' || r == '-':
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
	if flag&os.O_CREATE != 0 && os.IsNotExist(err) {
		err = syscall.Mkfifo(name, syscall.S_IFIFO|uint32(perm))
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("%q is not a named pipe", name)
	}

	flag &^= os.O_CREATE // remove os.O_CREATE flag used above
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
		event.Source.ID() != client.GetID() ||
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
	if event.Source == nil {
		return names, nil
	}

	user := client.LookupUser(event.Source.Name)
	if user == nil && client.GetID() == event.Source.ID() {
		return names, nil // User didn't join any channels yet
	} else if user == nil {
		return names, fmt.Errorf("user %q doesn't exist", event.Source.Name)
	}

	for _, dir := range ircDirs {
		if user.Nick == girc.ToRFC1459(dir.name) ||
			(dir.ch != nil && user.InChannel(dir.name)) ||
			(dir.name != masterChan && user.Nick == client.GetID()) {
			names = append(names, &dir.name)
		}
	}

	return names, nil
}

func getEventDirs(client *girc.Client, event *girc.Event) ([]*string, error) {
	name := masterChan
	if event.IsFromChannel() {
		name = event.Params[0]
	} else if event.IsFromUser() {
		name = event.Source.Name
		if event.Source.ID() == client.GetID() {
			name = event.Params[0]
		}
	} else {
		switch event.Command {
		case girc.QUIT, girc.NICK:
			return getSourceDirs(client, event)
		}

		channel, isChanCmd := getCmdChan(event)
		if isChanCmd {
			name = channel
		}
	}

	return []*string{&name}, nil
}

func storeName(dir *ircDir) error {
	tmpf, err := ioutil.TempFile(dir.fp, ".tmp"+idfn)
	if err != nil {
		return err
	}
	defer tmpf.Close()

	_, err = tmpf.WriteString(dir.name + "\n")
	if err != nil {
		os.Remove(tmpf.Name())
		return err
	}
	err = tmpf.Chmod(0400)
	if err != nil {
		os.Remove(tmpf.Name())
		return err
	}

	return os.Rename(tmpf.Name(), filepath.Join(dir.fp, idfn))
}

func createListener(client *girc.Client, name string) (*ircDir, error) {
	key := normalize(name)
	if idir, ok := ircDirs[key]; ok {
		return idir, errExist
	}

	dir := filepath.Join(ircPath, key)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, err
	}

	idir := &ircDir{name, make(chan bool, 1), dir, nil}
	if name != masterChan {
		err = storeName(idir)
		if err != nil {
			return nil, err
		}
	}
	ircDirs[key] = idir

	go recvInput(client, name, idir)
	if girc.IsValidChannel(name) {
		idir.ch = &ircChan{make(chan bool, 1), nil}
		go serveNicks(client, name, idir)
	} else if girc.IsValidNick(name) {
		client.Cmd.Monitor('+', name)
	}

	return idir, nil
}

func removeListener(name string) error {
	key := normalize(name)
	dir, ok := ircDirs[key]
	if !ok {
		return errNotExist
	}
	defer delete(ircDirs, key)

	infp := filepath.Join(dir.fp, infn)

	// hack to gracefully terminate the recvInput goroutine
	dir.done <- true
	fifo, err := openFifo(infp, os.O_WRONLY|syscall.O_NONBLOCK, 0600)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	defer os.Remove(infp)
	fifo.Close()

	ch := dir.ch
	if ch != nil && ch.ln != nil {
		ch.done <- true
		err := ch.ln.Close()
		if err != nil {
			return err
		}
	}

	return nil
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
	event := girc.ParseEvent(fmt.Sprintf(":%s %s", client.GetNick(), input))
	if event == nil {
		return nil
	}

	switch event.Command {
	case girc.PRIVMSG:
		client.RunHandlers(event)
	case girc.JOIN:
		var ch string
		if len(event.Params) > 0 {
			ch = event.Params[0]
		} else if len(event.Trailing) > 0 {
			ch = event.Trailing
		}

		if ch != "" {
			idir, ok := ircDirs[normalize(ch)]
			if ok && idir.name != ch {
				return fmt.Errorf("cannot join %q: name clash", ch)
			}
		}
	}

	return client.Cmd.SendRaw(input + "\r\n")
}

func recvInput(client *girc.Client, name string, dir *ircDir) {
	infp := filepath.Join(dir.fp, infn)
	for {
		fifo, err := openFifo(infp, os.O_CREATE|os.O_RDONLY, 0600)
		select {
		case <-dir.done:
			return
		default:
			if err != nil {
				die(err)
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

func serveNicks(client *girc.Client, name string, dir *ircDir) {
	nickfp := filepath.Join(dir.fp, nickfn)

	var err error
	dir.ch.ln, err = net.Listen("unix", nickfp)
	if err != nil {
		die(err)
	}

	for {
		conn, err := dir.ch.ln.Accept()
		select {
		case <-dir.ch.done:
			return
		default:
			if err != nil {
				log.Println(err)
				continue
			}

			ch := client.LookupChannel(name)
			if ch != nil {
				var b bytes.Buffer
				for _, user := range ch.Users(client) {
					b.WriteString(user.Nick + "\n")
				}
				_, err = conn.Write(b.Bytes())
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

	out = fmt.Sprintf("%v %s\n", event.Timestamp.Unix(), girc.StripRaw(out))
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

func writeEvent(client *girc.Client, event *girc.Event, name string) error {
	out, ok := fmtEvent(event, true)
	if !ok {
		return nil
	}

	idir, err := createListener(client, name)
	if err == errExist && idir.name != name {
		return fmt.Errorf("name clash (%q vs. %q)", idir.name, name)
	} else if err != nil && err != errExist {
		return err
	}

	outfp := filepath.Join(idir.fp, outfn)
	return appendFile(outfp, []byte(out), 0600)
}

func handleMonitor(client *girc.Client, event girc.Event) {
	targets := strings.Split(event.Trailing, ",")
	for _, target := range targets {
		source := girc.ParseSource(target)

		// User might have already been removed elsewhere or
		// added in writeEvent already. Thus we ignore the
		// double removal / creation error.

		var err, expErr error
		switch event.Command {
		case girc.RPL_MONOFFLINE:
			err = removeListener(source.Name)
			expErr = errNotExist
		case girc.RPL_MONONLINE:
			_, err = createListener(client, source.Name)
			expErr = errExist
		default:
			panic("Unexpected command")
		}

		if err != nil && err != expErr {
			log.Printf("Couldn't monitor %q: %s\n", target, err)
		}
	}
}

func handlePart(client *girc.Client, event girc.Event) {
	if len(event.Params) < 1 || event.Source == nil {
		return
	}
	name := event.Params[0]

	if event.Source.ID() == client.GetID() {
		err := removeListener(name)
		if err != nil {
			log.Printf("Couldn't remove %q after part: %s\n", name, err)
		}
	}
}

func handleKick(client *girc.Client, event girc.Event) {
	if len(event.Params) < 2 ||
		girc.ToRFC1459(event.Params[1]) != client.GetID() {
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
	case girc.AWAY, girc.CAP_ACCOUNT, girc.CAP_CHGHOST:
		return // Ignore, occurs too often.
	case girc.PRIVMSG:
		if isMention(client, &event) {
			err := writeMention(&event)
			if err != nil {
				log.Println(err)
			}
		}
	}

	names, err := getEventDirs(client, &event)
	if err != nil {
		die(err)
	}

	for _, name := range names {
		err := writeEvent(client, &event, *name)
		if err != nil {
			log.Println(err)
		}
	}
}

func addHandlers(client *girc.Client) {
	client.Handlers.Add(girc.CONNECTED, func(c *girc.Client, e girc.Event) {
		for _, target := range flag.Args()[1:] {
			if girc.IsValidChannel(target) {
				c.Cmd.Join(target)
			} else if girc.IsValidNick(target) {
				c.Cmd.Monitor('+', target)
			} else {
				log.Println("Invalid target %q\n", target)
			}
		}
	})

	client.Handlers.Add(girc.RPL_MONOFFLINE, handleMonitor)
	client.Handlers.Add(girc.RPL_MONONLINE, handleMonitor)

	client.Handlers.Add(girc.PART, handlePart)
	client.Handlers.Add(girc.KICK, handleKick)

	client.Handlers.Add(girc.ALL_EVENTS, handleMsg)
}

func newClient() (*girc.Client, error) {
	var tlsconf *tls.Config
	if useTLS {
		var err error
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
