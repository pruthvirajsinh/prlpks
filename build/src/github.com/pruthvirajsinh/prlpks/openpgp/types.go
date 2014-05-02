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
	"errors"
	"io"

	"code.google.com/p/go.crypto/openpgp/packet"
)

var ErrInvalidPacketType error = errors.New("Invalid packet type")
var ErrPacketRecordState error = errors.New("Packet record state has not been properly initialized")

// PacketState indicates the validity of the public key material and special
// policies that may apply to it. The lower 16 bits are either neutral policy
// or positive validation indicators. The upper 16 bits indicate validation failure
// that the key material is either invalid, unverifiable or failed to meet some policy
// criteria.
type PacketState int

const (
	// Bits 0-15 indicate positive verification status and public key policies

	// Key material has been registered with prlpks by the key owner,
	// who has signed a nonced challenge message with the associated private key.
	PacketStateRegistered = 1 << 0

	// Key material is cloaked. prlpks will respond as if the key does not exist
	// unless the HKP request has proper authentication.
	PacketStateCloaked = 1 << 1

	// Signature has been checked and verified
	PacketStateSigOk = 1 << 2

	// Bits 16-23 indicate verification failure of the key material.

	// Key material is banned from HKP results unconditionally. Could be signature
	// graphiti or other unwanted content.
	PacketStateSpam = 1 << 16

	// Key material is considered to be abandoned according to keyserver policy.
	PacketStateAbandoned = 1 << 17

	// Key material lacks a valid, non-expired self-signature
	PacketStateNoSelfSig = 1 << 18

	// Subkey material lacks a valid, non-expired binding-signature
	PacketStateNoBindingSig = 1 << 19

	// Public key is unsupported (unknown algorithm code, etc.)
	PacketStateUnsuppPubkey = 1 << 20
)

type PacketVisitor func(PacketRecord) error

type PacketRecord interface {
	GetOpaquePacket() (*packet.OpaquePacket, error)
	GetPacket() (packet.Packet, error)
	Read() error
	Serialize(w io.Writer) error
	setPacket(packet.Packet) error
	Uuid() string
	Visit(PacketVisitor) error
}

type publicKeyRecord interface {
	publicKey() *packet.PublicKey
	publicKeyV3() *packet.PublicKeyV3
}

type Signable interface {
	AddSignature(*Signature)
	RemoveSignature(*Signature)
}

func toOpaquePacket(buf []byte) (*packet.OpaquePacket, error) {
	r := packet.NewOpaqueReader(bytes.NewBuffer(buf))
	return r.Next()
}

type packetSlice []*packet.OpaquePacket

func (ps packetSlice) Len() int {
	return len(ps)
}

func (ps packetSlice) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

type sksPacketSorter struct{ packetSlice }

func (sps sksPacketSorter) Less(i, j int) bool {
	cmp := int32(sps.packetSlice[i].Tag) - int32(sps.packetSlice[j].Tag)
	if cmp < 0 {
		return true
	} else if cmp > 0 {
		return false
	}
	return bytes.Compare(sps.packetSlice[i].Contents, sps.packetSlice[j].Contents) < 0
}
