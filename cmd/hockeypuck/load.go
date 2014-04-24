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
	"fmt"
	"github.com/pruthvirajsinh/symflux"
	"github.com/pruthvirajsinh/symflux/recon"
	"github.com/lib/pq"
	"launchpad.net/gnuflag"
	"log"
	"os"
	"path/filepath"
	//	"strings"

	. "github.com/pruthvirajsinh/prlpks"
	"github.com/pruthvirajsinh/prlpks/openpgp"
)

type loadCmd struct {
	configuredCmd
	path       string
	txnSize    int
	ignoreDups bool

	db            *openpgp.DB
	l             *openpgp.Loader
	ptree         recon.PrefixTree
	nkeys         int
	inTransaction bool

	//PRC Start
	totalKeyLimit int
	//PRC End
}

func (ec *loadCmd) Name() string { return "load" }

func (ec *loadCmd) Desc() string { return "Load OpenPGP keyring files into database" }

func newLoadCmd() *loadCmd {
	cmd := new(loadCmd)
	flags := gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	flags.StringVar(&cmd.configPath, "config", "", "prlpks configuration file")
	flags.StringVar(&cmd.path, "path", "", "OpenPGP keyring file path or glob pattern")
	flags.IntVar(&cmd.txnSize, "txn-size", 5000, "Transaction size; public keys per commit")
	flags.BoolVar(&cmd.ignoreDups, "ignore-dups", false, "Ignore duplicate entries")
	flags.IntVar(&cmd.totalKeyLimit, "totalKeys", 0, "Limit the number of keys per load. 0 = all keys")

	cmd.flags = flags
	return cmd
}

func (ec *loadCmd) Main() {
	if ec.path == "" {
		Usage(ec, "--path is required")
	}
	if ec.txnSize < 1 {
		Usage(ec, "Invalid --txn-size, must be >= 1")
	}

	if ec.totalKeyLimit < 0 {
		Usage(ec, "Please enter positive total Keys")
	} else {
		fmt.Println("Starting loading of ", ec.totalKeyLimit, " keys")
	}
	ec.configuredCmd.Main()
	InitLog()
	var err error
	if ec.db, err = openpgp.NewDB(); err != nil {
		die(err)
	}
	ec.l = openpgp.NewLoader(ec.db, true)
	// Ensure tables all exist
	if err = ec.db.CreateTables(); err != nil {
		die(err)
	}
	reconSettings := recon.NewSettings(openpgp.Config().Settings.TomlTree)
	if ec.ptree, err = openpgp.NewSksPTree(reconSettings); err != nil {
		die(err)
	}
	// Create the prefix tree (if not exists)
	if err = ec.ptree.Create(); err != nil {
		die(fmt.Errorf("Unable to create prefix tree: %v", err))
	}
	// Ensure tables all exist
	if err = ec.db.CreateTables(); err != nil {
		die(fmt.Errorf("Unable to create database tables: %v", err))
	}
	// Load all keys from input material
	ec.loadAllKeys(ec.path)
	// Close the prefix tree
	if err = ec.ptree.Close(); err != nil {
		log.Println("Close ptree:", err)
	}
	// Close the database connection
	if err = ec.db.Close(); err != nil {
		log.Println("Close database:", err)
	}
}

func (ec *loadCmd) flushDb() {
	if ec.inTransaction {
		log.Println("Loaded", ec.nkeys, "keys")
		if err := ec.l.Commit(); err != nil {
			die(fmt.Errorf("Error committing transaction: %v", err))
		}
		ec.inTransaction = false
		ec.nkeys = 0
	}
}

func (ec *loadCmd) insertKey(keyRead *openpgp.ReadKeyResult) error {
	var err error
	if ec.nkeys%ec.txnSize == 0 {
		ec.flushDb()
		if _, err = ec.l.Begin(); err != nil {
			die(fmt.Errorf("Error starting new transaction: %v", err))
		}
		ec.inTransaction = true
	}
	// Load key into relational database
	if err = ec.l.InsertKey(keyRead.Pubkey); err != nil {
		log.Println("Error inserting key:", keyRead.Pubkey.Fingerprint(), ":", err)
		if _, is := err.(pq.Error); is {
			die(fmt.Errorf("Unable to load due to database errors."))
		}
	}
	ec.nkeys++
	return err
}

func (ec *loadCmd) loadAllKeys(path string) {
	keyfiles, err := filepath.Glob(path)
	if err != nil {
		die(err)
	}

	limit := ec.totalKeyLimit
	for _, keyfile := range keyfiles {
		var f *os.File
		if f, err = os.Open(keyfile); err != nil {
			log.Println("Failed to open", keyfile, ":", err)
			continue
		}
		defer f.Close()
		log.Println("Loading keys from", keyfile)
		defer ec.flushDb()
		for keyRead := range openpgp.ReadKeys(f) {
			if keyRead.Error != nil {
				log.Println("Error reading key:", keyRead.Error)
				continue
			}

			//PRC Start
			//Only load Keys which are in our own authority
			if keyRead.Pubkey == nil {
				fmt.Println("no Pub Key found")
				continue

			}
			underAuth := openpgp.IsUnderAuth(*keyRead.Pubkey)
			if underAuth != nil {
				fmt.Println("Load : " + underAuth.Error())
				continue
			}
			//PRC End

			digest, err := hex.DecodeString(keyRead.Pubkey.Md5)
			if err != nil {
				log.Println("bad digest:", keyRead.Pubkey.Md5)
				continue
			}
			digest = recon.PadSksElement(digest)
			digestZp := symflux.Zb(symflux.P_SKS, digest)
			err = ec.ptree.Insert(digestZp)
			if err != nil {
				log.Println("Error inserting digest ", keyRead.Pubkey.Md5, ":", err)
				continue
			}
			err = ec.insertKey(keyRead)
			if err != nil {
				log.Println("Error inserting key", keyRead.Pubkey.Md5, "into database:", err)
				// Attempt to remove digest from ptree, since it was not successfully loaded
				ec.ptree.Remove(digestZp)
				continue
			}
			if ec.totalKeyLimit != 0 {
				limit--
				if limit == 0 {
					fmt.Println("Loaded ", ec.totalKeyLimit, " keys")
					return
				}
			}
		}
	}

}
