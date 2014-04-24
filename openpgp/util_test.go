/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package openpgp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"code.google.com/p/go.crypto/openpgp/armor"

	"github.com/pruthvirajsinh/prlpks"
)

func init() {
	prlpks.SetConfig("")
}

func MustInput(t *testing.T, name string) *os.File {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Cannot locate unit test data files")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("Cannot open unit test data file", path, ":", err)
	}
	return f
}

func MustInputAscKeys(t *testing.T, name string) (result []*Pubkey) {
	f := MustInput(t, name)
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	for keyRead := range ReadKeys(block.Body) {
		if keyRead.Error != nil {
			t.Fatal(keyRead.Error)
		}
		result = append(result, keyRead.Pubkey)
	}
	return
}

func MustInputAscKey(t *testing.T, name string) *Pubkey {
	keys := MustInputAscKeys(t, name)
	if len(keys) != 1 {
		t.Fatal("Expected only one key, got", len(keys))
	}
	return keys[0]
}
