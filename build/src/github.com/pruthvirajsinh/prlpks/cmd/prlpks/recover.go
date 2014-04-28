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
	"log"

	"launchpad.net/gnuflag"
	. "github.com/pruthvirajsinh/prlpks"
	"github.com/pruthvirajsinh/prlpks/openpgp"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

type recoverCmd struct {
	configuredCmd
}

func (rc *recoverCmd) Name() string { return "recover" }

func (rc *recoverCmd) Desc() string { return "Recover prefix tree" }

func newRecoverCmd() *recoverCmd {
	cmd := new(recoverCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "prlpks configuration file")
	cmd.flags = flags
	return cmd
}

func (ec *recoverCmd) Main() {
	ec.configuredCmd.Main()
	InitLog()
	path := openpgp.Config().Settings.TomlTree.Get("symflux.recon.leveldb.path").(string)
	stor, err := storage.OpenFile(path)
	if err != nil {
		die(err)
	}
	log.Println("database storage opened, recovering...")
	db, err := leveldb.Recover(stor, nil)
	if err != nil {
		die(err)
	}
	log.Println("recovery complete")
	db.Close()
}
