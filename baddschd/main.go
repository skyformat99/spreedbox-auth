package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	baddsch "golang.struktur.de/spreedbox/spreedbox-auth/baddsch/server"

	"github.com/strukturag/phoenix"
	"golang.struktur.de/spreedbox/spreedbox-go/common"
)

var appVersion = "unreleased"
var defaultConfig = "./server.conf"
var logFilename string

func runner(runtime phoenix.Runtime) error {
	if logFilename == "" || logFilename == "syslog" {
		common.SetupLogfile(logFilename)
	}

	server, err := baddsch.NewServer()
	if err != nil {
		return err
	}

	return server.Serve(runtime)
}

func main() {
	configPath := flag.String("c", defaultConfig, "Configuration file.")
	showVersion := flag.Bool("v", false, "Display version number and exit.")
	memprofile := flag.String("memprofile", "", "Write memory profile to this file.")
	cpuprofile := flag.String("cpuprofile", "", "Write cpu profile to file.")
	showHelp := flag.Bool("h", false, "Show this usage information and exit.")
	flag.Parse()
	if err := common.SetupLogfile(common.GetLogfilename()); err != nil {
		log.Println("Could not setup logging:", err)
		os.Exit(1)
	}

	if *showHelp {
		flag.Usage()
		os.Exit(0)
	} else if *showVersion {
		fmt.Printf("Version %s\n", appVersion)
		os.Exit(0)
	}

	logFilename = common.GetLogfilename()
	if logFilename == "" || logFilename == "syslog" {
		common.SetupLogfile(logFilename)
	}

	err := phoenix.NewServer("baddschd", appVersion).
		Config(configPath).
		Log(&logFilename).
		CpuProfile(cpuprofile).
		MemProfile(memprofile).
		Run(runner)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Print("exiting")
}
