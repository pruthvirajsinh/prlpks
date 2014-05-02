package main

import (
	"net/http"

	"code.google.com/p/gorilla/mux"
	"launchpad.net/gnuflag"

	. "github.com/pruthvirajsinh/prlpks"
	"github.com/pruthvirajsinh/prlpks/hkp"
	"github.com/pruthvirajsinh/prlpks/openpgp"
)

type runCmd struct {
	configuredCmd
}

func (c *runCmd) Name() string { return "run" }

func (c *runCmd) Desc() string { return "Run prlpks services" }

func newRunCmd() *runCmd {
	cmd := new(runCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "prlpks configuration file")
	cmd.flags = flags
	return cmd
}

func (c *runCmd) Main() {
	c.configuredCmd.Main()
	InitLog()
	// Create an HTTP request router
	r := mux.NewRouter()
	// Add common static routes
	NewStaticRouter(r)
	// Create HKP router
	hkpRouter := hkp.NewRouter(r)
	// Create SKS peer
	sksPeer, err := openpgp.NewSksPeer(hkpRouter.Service)
	if err != nil {
		die(err)
	}
	// Launch the OpenPGP workers
	for i := 0; i < openpgp.Config().NumWorkers(); i++ {
		w, err := openpgp.NewWorker(hkpRouter.Service, sksPeer)
		if err != nil {
			die(err)
		}
		// Subscribe SKS to worker's key changes
		w.SubKeyChanges(sksPeer.KeyChanges)
		go w.Run()
	}
	sksPeer.Start()
	//PRC Start
	go openpgp.CheckImap()
	//PRC End
	// Bind the router to the built-in webserver root
	http.Handle("/", r)
	// Start the built-in webserver, run forever
	err = http.ListenAndServe(hkp.Config().HttpBind(), nil)
	die(err)
}
