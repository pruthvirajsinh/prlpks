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
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"sort"

	"time"
)

// Comparable time flag for "never expires"
var NeverExpires time.Time

var ErrMissingSignature = errors.New("Key material missing an expected signature")

func init() {
	t, err := time.Parse("2006-01-02 15:04:05 -0700", "9999-12-31 23:59:59 +0000")
	if err != nil {
		panic(err)
	}
	NeverExpires = t
}

// Get the public key fingerprint as a hex string.
func Fingerprint(pubkey *packet.PublicKey) string {
	return hex.EncodeToString(pubkey.Fingerprint[:])
}

// Get the public key fingerprint as a hex string.
func FingerprintV3(pubkey *packet.PublicKeyV3) string {
	return hex.EncodeToString(pubkey.Fingerprint[:])
}

func WritePackets(w io.Writer, root PacketRecord) error {
	err := root.Visit(func(rec PacketRecord) error {
		op, err := rec.GetOpaquePacket()
		if err != nil {
			return err
		}
		return op.Serialize(w)
	})
	if err != nil {
		return err
	}
	// Dump unsupported packets at the end.
	pubkey := root.(*Pubkey)
	for _, op := range pubkey.UnsupportedPackets() {
		err = op.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
}

func WriteArmoredPackets(w io.Writer, root PacketRecord) error {
	armw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	defer armw.Close()
	if err != nil {
		return err
	}
	return WritePackets(armw, root)
}

type OpaqueKeyring struct {
	Packets      []*packet.OpaquePacket
	RFingerprint string
	Md5          string
	Sha256       string
	Error        error
}

type OpaqueKeyringChan chan *OpaqueKeyring

func ReadOpaqueKeyrings(r io.Reader) OpaqueKeyringChan {
	c := make(OpaqueKeyringChan)
	or := packet.NewOpaqueReader(r)
	go func() {
		defer close(c)
		var op *packet.OpaquePacket
		var err error
		var current *OpaqueKeyring
		for op, err = or.Next(); err == nil; op, err = or.Next() {
			switch op.Tag {
			case 6: //packet.PacketTypePublicKey:
				if current != nil {
					c <- current
					current = nil
				}
				current = new(OpaqueKeyring)
				fallthrough
			case 13: //packet.PacketTypeUserId:
				fallthrough
			case 17: //packet.PacketTypeUserAttribute:
				fallthrough
			case 14: //packet.PacketTypePublicSubkey:
				fallthrough
			case 2: //packet.PacketTypeSignature:
				current.Packets = append(current.Packets, op)
			}
		}
		if err == io.EOF && current != nil {
			c <- current
		} else if err != nil {
			c <- &OpaqueKeyring{Error: err}
		}
	}()
	return c
}

// SksDigest calculates a cumulative message digest on all
// OpenPGP packets for a given primary public key,
// using the same ordering as SKS, the Synchronizing Key Server.
// Use MD5 for matching digest values with SKS.
func SksDigest(key *Pubkey, h hash.Hash) string {
	var packets packetSlice
	key.Visit(func(rec PacketRecord) error {
		if opkt, err := rec.GetOpaquePacket(); err != nil {
			panic(fmt.Sprintf(
				"Error parsing packet: %v public key fingerprint: %v", err, key.Fingerprint()))
		} else {
			packets = append(packets, opkt)
		}
		return nil
	})
	packets = append(packets, key.UnsupportedPackets()...)
	return sksDigestOpaque(packets, h)
}

func sksDigestOpaque(packets []*packet.OpaquePacket, h hash.Hash) string {
	sort.Sort(sksPacketSorter{packets})
	for _, opkt := range packets {
		binary.Write(h, binary.BigEndian, int32(opkt.Tag))
		binary.Write(h, binary.BigEndian, int32(len(opkt.Contents)))
		h.Write(opkt.Contents)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type ReadKeyResult struct {
	*Pubkey
	Error error
}

type ReadKeyResults []*ReadKeyResult

func (r ReadKeyResults) GoodKeys() (result []*Pubkey) {
	for _, rkr := range r {
		if rkr.Error == nil {
			result = append(result, rkr.Pubkey)
		}
	}
	return
}

type PubkeyChan chan *ReadKeyResult

func ErrReadKeys(msg string) *ReadKeyResult {
	return &ReadKeyResult{Error: errors.New(msg)}
}

func (pubkey *Pubkey) updateDigests() {
	pubkey.Md5 = SksDigest(pubkey, md5.New())
	pubkey.Sha256 = SksDigest(pubkey, sha256.New())
}

func ReadKeys(r io.Reader) PubkeyChan {
	c := make(PubkeyChan)
	go func() {
		defer close(c)
		for keyRead := range readKeys(r) {
			if keyRead.Error == nil {
				Resolve(keyRead.Pubkey)
			}
			c <- keyRead
		}
	}()
	return c
}

func dumpBadKey(opkr *OpaqueKeyring) {
	f, err := ioutil.TempFile("", "prlpks-badkey")
	if err != nil {
		log.Println("Failed to dump bad key to temp file:", err)
		return
	}
	defer f.Close()
	for _, pkt := range opkr.Packets {
		err = pkt.Serialize(f)
		if err != nil {
			log.Println("Error writing bad key to temp file:", err)
			return
		}
	}
	log.Println("Bad key written to", f.Name())
}

// Read one or more public keys from input.
func readKeys(r io.Reader) PubkeyChan {
	c := make(PubkeyChan)
	go func() {
		defer close(c)
		var err error
		var pubkey *Pubkey
		var signable Signable
		for opkr := range ReadOpaqueKeyrings(r) {
			pubkey = nil
			for _, opkt := range opkr.Packets {
				var badPacket *packet.OpaquePacket
				switch opkt.Tag {
				case 6: //packet.PacketTypePublicKey:
					if pubkey != nil {
						log.Println("On pubkey:", pubkey)
						log.Println("Found embedded primary pubkey:", opkt)
						panic("Multiple primary public keys in keyring")
					}
					if pubkey, err = NewPubkey(opkt); err != nil {
						log.Println("On (opaque) pubkey:", opkt)
						log.Println(err)
						dumpBadKey(opkr)
						panic("Failed to parse primary pubkey")
					}
					signable = pubkey
				case 14: //packet.PacketTypePublicSubkey:
					var subkey *Subkey
					if subkey, err = NewSubkey(opkt); err != nil {
						badPacket = opkt
						signable = nil
					} else {
						pubkey.subkeys = append(pubkey.subkeys, subkey)
						signable = subkey
					}
				case 13: //packet.PacketTypeUserId:
					var userId *UserId
					if userId, err = NewUserId(opkt); err != nil {
						badPacket = opkt
						signable = nil
					} else {
						pubkey.userIds = append(pubkey.userIds, userId)
						signable = userId
					}
				case 17: //packet.PacketTypeUserAttribute:
					var userAttr *UserAttribute
					if userAttr, err = NewUserAttribute(opkt); err != nil {
						badPacket = opkt
						signable = nil
					} else {
						pubkey.userAttributes = append(pubkey.userAttributes, userAttr)
						signable = userAttr
					}
				case 2: //packet.PacketTypeSignature:

					var sig *Signature
					if sig, err = NewSignature(opkt); err != nil {
						badPacket = opkt
						signable = nil
					} else if signable == nil {
						badPacket = opkt
					} else {
						signable.AddSignature(sig)
						//fmt.Println("io.go:289>added sig => ", sig.Signature)
					}

				default:
					badPacket = opkt
				}
				if badPacket != nil {
					pubkey.AppendUnsupported(badPacket)
				}
			}
			if pubkey == nil {
				c <- &ReadKeyResult{Error: errors.New("No primary public key found")}
				continue
			}
			// Update the overall public key material digest.
			pubkey.updateDigests()
			// Validate signatures and wire-up relationships.
			// Also flags invalid key material but does not remove it.
			Resolve(pubkey)
			c <- &ReadKeyResult{Pubkey: pubkey}
		}
	}()
	return c
}
