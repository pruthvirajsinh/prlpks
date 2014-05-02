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
	"crypto/sha256"
	"fmt"
	"testing"

	"code.google.com/p/go.crypto/openpgp/armor"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/pruthvirajsinh/prlpks"
)

func connectString() string {
	return fmt.Sprintf(
		"dbname=postgres host=/var/run/postgresql sslmode=disable user=%s", currentUsername())
}

func MustCreateWorker(t *testing.T) *Worker {
	db, err := sqlx.Connect("postgres", connectString())
	assert.Nil(t, err)
	db.Execf("DROP DATABASE IF EXISTS testhkp")
	db.Execf("CREATE DATABASE testhkp")
	prlpks.SetConfig(fmt.Sprintf(`
[prlpks.openpgp.db]
driver="postgres"
dsn="dbname=testhkp host=/var/run/postgresql sslmode=disable user=%s"
`, currentUsername()))
	w, err := NewWorker(nil, nil)
	assert.Nil(t, err)
	return w
}

func MustDestroyWorker(t *testing.T, w *Worker) {
	w.db.Close()
	db, err := sqlx.Connect("postgres", connectString())
	assert.Nil(t, err)
	db.Close()
}

func TestValidateKey(t *testing.T) {
	f := MustInput(t, "tails.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	var keys []*Pubkey
	for keyRead := range ReadKeys(block.Body) {
		keys = append(keys, keyRead.Pubkey)
	}
	assert.Equal(t, 1, len(keys))
	assert.Equal(t, 2, len(keys[0].userIds))
	for i := 0; i < 2; i++ {
		assert.NotEmpty(t, keys[0].userIds[i].ScopedDigest)
	}
}

func TestRoundTripKeys(t *testing.T) {
	for _, testfile := range []string{
		"sksdigest.asc", "alice_signed.asc", "alice_unsigned.asc",
		"uat.asc", "tails.asc"} {
		t.Log(testfile)
		testRoundTripKey(t, testfile)
	}
}

func testRoundTripKey(t *testing.T, testfile string) {
	w := MustCreateWorker(t)
	defer MustDestroyWorker(t, w)
	key1 := MustInputAscKey(t, testfile)
	Resolve(key1)
	_, err := w.Begin()
	assert.Nil(t, err)
	err = w.InsertKey(key1)
	assert.Nil(t, err)
	err = w.Commit()
	assert.Nil(t, err)
	key2, err := w.fetchKey(key1.RFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	h1 := SksDigest(key1, sha256.New())
	h2 := SksDigest(key2, sha256.New())
	assert.Equal(t, h1, h2)
}
