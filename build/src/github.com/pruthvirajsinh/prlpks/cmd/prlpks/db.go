/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// prlpks is an OpenPGP keyserver.
package main

import (
	"launchpad.net/gnuflag"

	. "github.com/pruthvirajsinh/prlpks"
	"github.com/pruthvirajsinh/prlpks/openpgp"
)

type dbCmd struct {
	configuredCmd
	crTables      bool
	drConstraints bool
	dedup         bool
	crConstraints bool
}

func (c *dbCmd) Name() string { return "db" }

func (c *dbCmd) Desc() string {
	return "OpenPGP database maintenance operations"
}

func newDbCmd() *dbCmd {
	cmd := new(dbCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "prlpks configuration file")
	flags.BoolVar(&cmd.crTables, "create-tables", true, "Create tables if they don't exist")
	flags.BoolVar(&cmd.drConstraints, "drop-constraints", false,
		"Drop all primary key, unique and foreign key constraints")
	flags.BoolVar(&cmd.dedup, "dedup", false, "De-duplicate primary key and unique constraint columns")
	flags.BoolVar(&cmd.crConstraints, "create-constraints", false,
		"Create primary key, unique and foreign key constraints")
	cmd.flags = flags
	return cmd
}

func (c *dbCmd) Main() {
	c.configuredCmd.Main()
	InitLog()
	var db *openpgp.DB
	var err error
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if c.crTables {
		if err = db.CreateTables(); err != nil {
			die(err)
		}
	}
	// Drop constraints
	if c.drConstraints {
		// Create all constraints
		if err = db.DropConstraints(); err != nil {
			die(err)
		}
	}
	// De-duplication option
	if c.dedup {
		if err = db.DeleteDuplicates(); err != nil {
			die(err)
		}
	}
	// Create all constraints
	if c.crConstraints {
		if err = db.CreateConstraints(); err != nil {
			die(err)
		}
	}
}
