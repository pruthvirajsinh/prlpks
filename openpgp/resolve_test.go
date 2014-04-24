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
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"testing"

	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
)

func TestBadSelfSigUid(t *testing.T) {
	f := MustInput(t, "badselfsig.asc")
	i := 0
	for keyRead := range ReadKeys(f) {
		assert.NotNil(t, keyRead.Error)
		i++
	}
	assert.Equal(t, 1, i)
}

func TestDupSig(t *testing.T) {
	{
		f := MustInput(t, "252B8B37.dupsig.asc")
		defer f.Close()
		block, err := armor.Decode(f)
		if err != nil {
			t.Fatal(err)
		}
		r := packet.NewOpaqueReader(block.Body)
		var packets []*packet.OpaquePacket
		for {
			if op, err := r.Next(); err != nil {
				break
			} else {
				packets = append(packets, op)
				t.Log("raw:", op)
			}
		}
		sksDigest := sksDigestOpaque(packets, md5.New())
		assert.Equal(t, sksDigest, "6d57b48c83d6322076d634059bb3b94b")
	}
	// Read a key
	{
		f := MustInput(t, "252B8B37.dupsig.asc")
		defer f.Close()
		block, err := armor.Decode(f)
		if err != nil {
			t.Fatal(err)
		}
		var key *Pubkey
		for keyRead := range readKeys(block.Body) {
			assert.Nil(t, keyRead.Error)
			key = keyRead.Pubkey
		}
		var packets []*packet.OpaquePacket
		key.Visit(func(rec PacketRecord) error {
			op, err := rec.GetOpaquePacket()
			assert.Nil(t, err)
			packets = append(packets, op)
			return err
		})
		r := packet.NewOpaqueReader(bytes.NewBuffer(key.Unsupported))
		for op, err := r.Next(); err == nil; op, err = r.Next() {
			packets = append(packets, op)
		}
		sksDigest := sksDigestOpaque(packets, md5.New())
		assert.Equal(t, sksDigest, "6d57b48c83d6322076d634059bb3b94b")
	}
	// Now read & resolve
	key := MustInputAscKey(t, "252B8B37.dupsig.asc")
	key.Visit(func(rec PacketRecord) error {
		op, err := rec.GetOpaquePacket()
		assert.Nil(t, err)
		t.Log("parsed:", op)
		return nil
	})
	r := packet.NewOpaqueReader(bytes.NewBuffer(key.Unsupported))
	for op, err := r.Next(); err == nil; op, err = r.Next() {
		t.Log("parsed:", op)
	}
	assert.Equal(t, key.Md5, "6d57b48c83d6322076d634059bb3b94b")
}

func TestPrimaryUidSelection(t *testing.T) {
	key := MustInputAscKey(t, "lp1195901.asc")
	Resolve(key)
	assert.NotNil(t, key.primaryUid)
	// Primary UID
	assert.Equal(t, key.primaryUid.Keywords, "Phil Pennock <phil.pennock@spodhuis.org>")
	for _, uid := range key.userIds {
		if uid.Keywords == "pdp@spodhuis.demon.nl" {
			// This uid sig is revoked
			assert.NotNil(t, uid.revSig)
		}
	}
	key = MustInputAscKey(t, "lp1195901_2.asc")
	Resolve(key)
	assert.NotNil(t, key.primaryUid)
	assert.Equal(t, key.primaryUid.Keywords, "Phil Pennock <phil.pennock@globnix.org>")
}

func TestSortPrimaryUid(t *testing.T) {
	key := MustInputAscKey(t, "lp1195901.asc")
	Resolve(key)
	Sort(key)
	expect := []string{
		"Phil Pennock <phil.pennock@spodhuis.org>",
		"Phil Pennock <phil.pennock@globnix.org>",
		"Phil Pennock <pdp@exim.org>",
		"Phil Pennock <pdp@spodhuis.org>",
		"Phil Pennock <pdp@spodhuis.demon.nl>"}
	for i := range key.userIds {
		assert.Equal(t, expect[i], key.userIds[i].Keywords)
	}
}

func TestKeyExpiration(t *testing.T) {
	key := MustInputAscKey(t, "lp1195901.asc")
	Resolve(key)
	Sort(key)
	key.Visit(func(rec PacketRecord) error {
		if sig, is := rec.(*Signature); is {
			if sig.Signature != nil && sig.Signature.KeyLifetimeSecs != nil {
				t.Logf("Key expiration %d", *sig.Signature.KeyLifetimeSecs)
			}
		}
		return nil
	})
}

func TestPrimaryUidFallback(t *testing.T) {
	f := MustInput(t, "snowcrash.gpg")
	var key *Pubkey
	for keyRead := range ReadKeys(f) {
		assert.Nil(t, keyRead.Error)
		key = keyRead.Pubkey
	}
	assert.NotNil(t, key)
	assert.NotEmpty(t, key.PrimaryUid)
	t.Log(key.PrimaryUid)
}

// TestUnsuppIgnored tests parsing key material containing
// packets which are not normally part of an exported public key --
// trust packets, in this case.
func TestUnsuppIgnored(t *testing.T) {
	f := MustInput(t, "snowcrash.gpg")
	var key *Pubkey
	for keyRead := range ReadKeys(f) {
		assert.Nil(t, keyRead.Error)
		key = keyRead.Pubkey
	}
	assert.NotNil(t, key)
	assert.Empty(t, key.Unsupported)
}

func TestMissingUidFk(t *testing.T) {
	key := MustInputAscKey(t, "d7346e26.asc")
	t.Log(key)
}

func TestV3NoUidSig(t *testing.T) {
	key := MustInputAscKey(t, "0xd46b7c827be290fe4d1f9291b1ebc61a.asc")
	assert.Equal(t, "0005127a8b7da8c32998d7e81dc92540", key.Md5)
	assert.Equal(t, "0760df64b3d82239", key.KeyId())
	f := MustInput(t, "0xd46b7c827be290fe4d1f9291b1ebc61a.asc")
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	var kr *OpaqueKeyring
	for opkr := range ReadOpaqueKeyrings(block.Body) {
		kr = opkr
	}
	sort.Sort(sksPacketSorter{kr.Packets})
	h := md5.New()
	for _, opkt := range kr.Packets {
		binary.Write(h, binary.BigEndian, int32(opkt.Tag))
		binary.Write(h, binary.BigEndian, int32(len(opkt.Contents)))
		h.Write(opkt.Contents)
	}
	md5 := hex.EncodeToString(h.Sum(nil))
	assert.Equal(t, "0005127a8b7da8c32998d7e81dc92540", md5)
}
