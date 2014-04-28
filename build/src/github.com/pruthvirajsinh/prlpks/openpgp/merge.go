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
	"errors"
)

type PacketRecordMap map[string]PacketRecord

var ErrMissingUuid error = errors.New("Packet record missing content-unique identifier")

func GetUuid(rec PacketRecord) string {
	switch r := rec.(type) {
	case *Pubkey:
		return r.RFingerprint
	case *Signature:
		return r.ScopedDigest
	case *UserId:
		return r.ScopedDigest
	case *UserAttribute:
		return r.ScopedDigest
	case *Subkey:
		return r.RFingerprint
	}
	return ""
}

func (m PacketRecordMap) Add(rec PacketRecord) error {
	uuid := GetUuid(rec)
	if uuid == "" {
		return ErrMissingUuid
	} else if _, ok := m[uuid]; !ok {
		m[uuid] = rec
	}
	return nil
}

// Map a tree of packet objects by strong hash.
func MapKey(pubkey *Pubkey) PacketRecordMap {
	m := make(PacketRecordMap)
	pubkey.Visit(m.Add)
	return m
}

// Merge the contents of srcKey into dstKey, modifying in-place.
// Packets in src not found in dst are appended to the matching parent.
// Conflicting packets and unmatched parents are ignored.
func MergeKey(dstKey *Pubkey, srcKey *Pubkey) {
	dstObjects := MapKey(dstKey)
	// Track source signable object in source traversal
	var srcSignable PacketRecord
	srcKey.Visit(func(srcObj PacketRecord) error {
		// Match in destination tree
		_, dstHas := dstObjects[GetUuid(srcObj)]
		switch so := srcObj.(type) {
		case *Pubkey:
			srcSignable = so
		case *Subkey:
			srcSignable = so
			if !dstHas {
				dstKey.subkeys = append(dstKey.subkeys, so)
			}
		case *UserId:
			srcSignable = so
			if !dstHas {
				dstKey.userIds = append(dstKey.userIds, so)
			}
		case *UserAttribute:
			srcSignable = so
			if !dstHas {
				dstKey.userAttributes = append(dstKey.userAttributes, so)
			}
		case *Signature:
			dstParent, dstHasParent := dstObjects[GetUuid(srcSignable)]
			dstSignable, isSignable := dstParent.(Signable)
			if !dstHas && dstHasParent && isSignable {
				dstSignable.AddSignature(so)
			}
		}
		return nil
	})
	dstKey.updateDigests()
	Resolve(dstKey)
}
