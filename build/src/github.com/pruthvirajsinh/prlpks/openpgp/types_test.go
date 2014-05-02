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

func TestVisitor(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	t.Log(key.userIds[0].signatures[0])
	var npub, nuid, nsub, nsig int
	key.Visit(func(rec PacketRecord) error {
		switch rec.(type) {
		case *Pubkey:
			npub++
		case *UserId:
			nuid++
		case *Subkey:
			nsub++
		case *Signature:
			nsig++
		}
		return nil
	})
	assert.Equal(t, 1, npub)
	assert.Equal(t, 1, nuid)
	assert.Equal(t, 1, nsub)
	assert.Equal(t, 2, nsig)
}

func TestIterOpaque(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	hits := make(map[uint8]int)
	for _, tag := range []uint8{
		2, 6, 13, 14} {
		//P.PacketTypeSignature, P.PacketTypePublicKey,
		//P.PacketTypeUserId, P.PacketTypePublicSubkey} {
		hits[tag] = 0
	}
	err := key.Visit(func(rec PacketRecord) error {
		if opkt, err := rec.GetOpaquePacket(); err == nil {
			hits[opkt.Tag]++
		}
		return nil
	})
	assert.Nil(t, err)
	t.Log(hits)
	assert.Equal(t, 2, hits[2 /*P.PacketTypeSignature*/])
	assert.Equal(t, 1, hits[6 /*P.PacketTypePublicKey*/])
	assert.Equal(t, 1, hits[13 /*P.PacketTypeUserId*/])
	assert.Equal(t, 1, len(key.userIds))
	assert.Equal(t, 1, len(key.userIds[0].signatures))
	assert.Equal(t, 1, hits[14 /*P.PacketTypePublicSubkey*/])
	assert.Equal(t, 1, len(key.subkeys[0].signatures))
	assert.Equal(t, 4, len(hits))
}
