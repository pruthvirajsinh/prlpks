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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMergeAddSig(t *testing.T) {
	unsignedKeys := MustInputAscKeys(t, "alice_unsigned.asc")
	assert.Equal(t, 1, len(unsignedKeys))
	signedKeys := MustInputAscKeys(t, "alice_signed.asc")
	assert.Equal(t, 1, len(signedKeys))
	expectedSigCount := func(key *Pubkey) (count int) {
		key.Visit(func(rec PacketRecord) error {
			switch r := rec.(type) {
			case *Signature:
				if r.IssuerKeyId() == "62aea01d67640fb5" {
					count++
				}
			}
			return nil
		})
		return
	}
	assert.Equal(t, 0, expectedSigCount(unsignedKeys[0]))
	assert.Equal(t, 1, expectedSigCount(signedKeys[0]))
	MergeKey(unsignedKeys[0], signedKeys[0])
	assert.Equal(t, 1, expectedSigCount(unsignedKeys[0]))
}
