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
	"encoding/hex"

	"log"

	"github.com/pruthvirajsinh/symflux"
	"github.com/pruthvirajsinh/symflux/recon"

	"launchpad.net/gnuflag"
	. "github.com/pruthvirajsinh/prlpks"
	"github.com/pruthvirajsinh/prlpks/openpgp"
)

type deleteCmd struct {
	configuredCmd
	keyHash string
}

func (ec *deleteCmd) Name() string { return "delete" }

func (ec *deleteCmd) Desc() string { return "Delete key hash from prefix tree" }

func newDeleteCmd() *deleteCmd {
	cmd := new(deleteCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "prlpks configuration file")
	flags.StringVar(&cmd.keyHash, "keyHash", "", "Delete key hash")
	cmd.flags = flags
	return cmd
}

func (ec *deleteCmd) Main() {
	if ec.keyHash == "" {
		Usage(ec, "--keyHash is required")
	}
	keyHash, err := hex.DecodeString(ec.keyHash)
	if err != nil {
		die(err)
	}
	ec.configuredCmd.Main()
	InitLog()
	var db *openpgp.DB
	if db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	var ptree recon.PrefixTree
	reconSettings := recon.NewSettings(openpgp.Config().Settings.TomlTree)
	if ptree, err = openpgp.NewSksPTree(reconSettings); err != nil {
		die(err)
	}
	// Create the prefix tree (if not exists)
	if err = ptree.Create(); err != nil {
		die(err)
	}
	// Ensure tables all exist
	if err = db.CreateTables(); err != nil {
		die(err)
	}
	if err = ptree.Remove(symflux.Zb(symflux.P_SKS, keyHash)); err != nil {
		die(err)
	}
	log.Println(ec.keyHash, "deleted from prefix tree")
}
