package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gorilla/mux"
	"github.com/strukturag/phoenix"
	"github.com/strukturag/sloth"
	"golang.struktur.de/spreedbox/spreedbox-auth/baddsch"
	"golang.struktur.de/spreedbox/spreedbox-go/common"
)

var appVersion = "unreleased"
var defaultConfig = "./server.conf"
var logFilename string

func runner(runtime phoenix.Runtime) error {
	if logFilename == "" || logFilename == "syslog" {
		common.SetupLogfile(logFilename)
	}

	router := mux.NewRouter()
	// HTTP listener support.
	if _, err := runtime.GetString("http", "listen"); err == nil {
		runtime.DefaultHTTPHandler(router)
	}

	api := sloth.NewAPI()
	api.SetMux(router.PathPrefix("/api/v1/").Subrouter())
	_, err := baddsch.NewAPIv1(api, runtime)
	if err != nil {
		return err
	}

	return runtime.Start()
}

func boot() error {
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
		return nil
	} else if *showVersion {
		fmt.Printf("Version %s\n", appVersion)
		return nil
	}

	logFilename = common.GetLogfilename()
	if logFilename == "" || logFilename == "syslog" {
		common.SetupLogfile(logFilename)
	}

	return phoenix.NewServer("baddschd", appVersion).
		Config(configPath).
		Log(&logFilename).
		CpuProfile(cpuprofile).
		MemProfile(memprofile).
		Run(runner)
}

func main() {
	if err := boot(); err != nil {
		log.Fatal("startup failed")
	}
}
