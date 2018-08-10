package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/lrstanley/girc"
)

var ircPath string

const (
	outfn = "out"
	infn  = "in"
)

var (
	clientCert string
	certs      string
	name       string
	prefix     string
	nick       string
	port       int
	server     string
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "USAGE: %s [FLAGS] [CHAN...]\n\n"+
		"The following flags are supported:\n\n", os.Args[0])
	flag.PrintDefaults()
}

func parseFlags() {
	user, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// Flags are declared in this function instead of declaring them
	// globally directly in order to properly utilize the os/user package.

	flag.StringVar(&clientCert, "a", "", "client certificates")
	flag.StringVar(&certs, "c", "", "root certificates")
	flag.StringVar(&name, "f", user.Name, "real name")
	flag.StringVar(&prefix, "i", filepath.Join(user.HomeDir, "irc"), "directory path")
	flag.StringVar(&nick, "n", user.Username, "nick")
	flag.IntVar(&port, "p", 6667, "TCP port")
	flag.StringVar(&server, "s", "irc.freenode.net", "IRC server")

	flag.Parse()
}

// See: RFC 1459, Section 4.2 (excluding List and Invite).
// All of these have the channel name as the first parameter (if any).
func isChannelOp(o string) bool {
	return (o == "JOIN" || o == "PART" || o == "MODE" ||
		o == "TOPIC" || o == "NAMES" || o == "LIST")
}

func normalize(name string) string {
	return name // TODO
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

func handleMsg(client *girc.Client, event girc.Event) {
	if event.Source == nil {
		return
	}

	dir := ircPath
	if isChannelOp(event.Command) && len(event.Params) >= 1 {
		dir = filepath.Join(dir, normalize(event.Params[0]))
	} else if event.Source.Ident != "" && event.Source.Host != "" {
		dir = filepath.Join(dir, normalize(event.Source.Name))
	}

	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatal(err)
	}

	outfp := filepath.Join(dir, outfn)
	err = appendFile(outfp, append(event.Bytes(), byte('\n')), 0600)
	if err != nil {
		log.Printf("Couldn't write to %q: %s\n", outfp, err)
	}
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

	// TODO: Set TLSConfig member
	client := girc.New(girc.Config{
		Server: server,
		Port:   port,
		Nick:   nick,
		User:   name,
	})

	quit := make(chan bool)
	client.Handlers.Add(girc.DISCONNECTED, func(c *girc.Client, e girc.Event) {
		quit <- true
	})

	// XXX: Just for testing purposes
	client.Handlers.Add(girc.ALL_EVENTS, handleMsg)
	client.Handlers.Add(girc.CONNECTED, func(c *girc.Client, e girc.Event) {
		c.Cmd.Join("#hii")
	})

	err = client.Connect()
	if err != nil {
		log.Fatal(err)
	}

	<-quit
}
