/*
   PRL PKS - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// prlpks is an OpenPGP keyserver.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"

	"launchpad.net/gnuflag"
	. "github.com/pruthvirajsinh/prlpks"
)

func die(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

type cmdHandler interface {
	Name() string
	Desc() string
	Flags() *gnuflag.FlagSet
	Main()
}

type subCmd struct {
	flags *gnuflag.FlagSet
}

func (c subCmd) Flags() *gnuflag.FlagSet { return c.flags }

func Usage(h cmdHandler, msg string) {
	fmt.Fprintln(os.Stderr, msg)
	fmt.Fprintf(os.Stderr, "\n  %s %s\t\t%s\n\n",
		filepath.Base(os.Args[0]), h.Name(), h.Desc())
	if h.Flags() != nil {
		h.Flags().PrintDefaults()
	}
	os.Exit(1)
}

var cmds []cmdHandler = []cmdHandler{
	newRunCmd(),
	newDeleteCmd(),
	newLoadCmd(),
	newRecoverCmd(),
	newDbCmd(),
	newPbuildCmd(),
	newHelpCmd(),
	newVersionCmd()}

func main() {
	if len(os.Args) < 2 {
		newHelpCmd().Main()
		return
	}
	var cmdArgs []string
	if len(os.Args) > 2 {
		cmdArgs = os.Args[2:]
	}
	var cpuProf bool
	for _, cmd := range cmds {
		if cmd.Name() == os.Args[1] {
			if flags := cmd.Flags(); flags != nil {
				flags.BoolVar(&cpuProf, "cpuprof", false, "Enable CPU profiling")
				flags.Parse(false, cmdArgs)
			}
			if cpuProf {
				if f, err := ioutil.TempFile("", "prlpks-cpuprof"); err == nil {
					defer f.Close()
					pprof.StartCPUProfile(f)
					defer pprof.StopCPUProfile()
				} else {
					log.Println("Warning: Failed to open tempfile for cpuprof:", err)
				}
			}
			cmd.Main()
			return
		}
	}
	newHelpCmd().Main()
}

type helpCmd struct {
	subCmd
}

func (c *helpCmd) Name() string { return "help" }

func (c *helpCmd) Desc() string { return "Display this help message" }

func (c *helpCmd) Main() {
	fmt.Fprintln(os.Stderr, `PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

Basic commands:
`)
	for _, cmd := range cmds {
		fmt.Fprintf(os.Stderr, "  %s %s\t\t%s\n",
			filepath.Base(os.Args[0]), cmd.Name(), cmd.Desc())
	}
	os.Exit(1)
}

func newHelpCmd() *helpCmd {
	return new(helpCmd)
}

type versionCmd struct {
	subCmd
}

func (c *versionCmd) Name() string { return "version" }

func (c *versionCmd) Desc() string { return "Display PRL PKS version information" }

func (c *versionCmd) Main() {
	fmt.Println(Version)
	os.Exit(0)
}

func newVersionCmd() *versionCmd {
	return new(versionCmd)
}

type configuredCmd struct {
	subCmd
	configPath string
}

func (c configuredCmd) Main() {
	if c.configPath != "" {
		if err := LoadConfigFile(c.configPath); err != nil {
			die(err)
		}
	} else {
		// Fall back on default empty config
		SetConfig("")
	}
}
