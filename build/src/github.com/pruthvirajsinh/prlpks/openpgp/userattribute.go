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
	"crypto/sha256"
	"database/sql"
	"io"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp/packet"
)

type UserAttribute struct {
	ScopedDigest string         `db:"uuid"`        // immutable
	Creation     time.Time      `db:"creation"`    // mutable (derived from latest sigs)
	Expiration   time.Time      `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       []byte         `db:"packet"`      // immutable
	PubkeyRFP    string         `db:"pubkey_uuid"` // immutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable

	/* Cross-references */

	revSig        *Signature   `db:"-"`
	selfSignature *Signature   `db:"-"`
	signatures    []*Signature `db:"-"`

	/* Parsed packet data */

	UserAttribute *packet.UserAttribute
}

func (uat *UserAttribute) calcScopedDigest(pubkey *Pubkey) string {
	h := sha256.New()
	h.Write([]byte(pubkey.RFingerprint))
	h.Write([]byte("{uat}"))
	h.Write(uat.Packet)
	return toAscii85String(h.Sum(nil))
}

func (uat *UserAttribute) Serialize(w io.Writer) error {
	_, err := w.Write(uat.Packet)
	return err
}

func (uat *UserAttribute) Uuid() string { return uat.ScopedDigest }

func (uat *UserAttribute) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(uat.Packet)
}

func (uat *UserAttribute) GetPacket() (packet.Packet, error) {
	if uat.UserAttribute != nil {
		return uat.UserAttribute, nil
	}
	return nil, ErrPacketRecordState
}

func (uat *UserAttribute) setPacket(p packet.Packet) error {
	u, is := p.(*packet.UserAttribute)
	if !is {
		return ErrInvalidPacketType
	}
	uat.UserAttribute = u
	return nil
}

func (uat *UserAttribute) Read() (err error) {
	buf := bytes.NewBuffer(uat.Packet)
	var p packet.Packet
	if p, err = packet.Read(buf); err != nil {
		return err
	}
	return uat.setPacket(p)
}

func NewUserAttribute(op *packet.OpaquePacket) (uat *UserAttribute, err error) {
	var buf bytes.Buffer
	if err = op.Serialize(&buf); err != nil {
		return
	}
	uat = &UserAttribute{Packet: buf.Bytes()}
	var p packet.Packet
	if p, err = op.Parse(); err != nil {
		return
	}
	if err = uat.setPacket(p); err != nil {
		return
	}
	return uat, uat.init()
}

func (uat *UserAttribute) init() (err error) {
	uat.Creation = NeverExpires
	uat.Expiration = time.Unix(0, 0)
	return
}

func (uat *UserAttribute) Visit(visitor PacketVisitor) (err error) {
	err = visitor(uat)
	if err != nil {
		return
	}
	for _, sig := range uat.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
}

func (uat *UserAttribute) AddSignature(sig *Signature) {
	uat.signatures = append(uat.signatures, sig)
}

func (uat *UserAttribute) RemoveSignature(sig *Signature) {
	uat.signatures = removeSignature(uat.signatures, sig)
}

func (uat *UserAttribute) linkSelfSigs(pubkey *Pubkey) {
	for _, sig := range uat.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if sig.SigType == 0x30 { // TODO: add packet.SigTypeCertRevocation
			if uat.revSig == nil || sig.Creation.Unix() > uat.revSig.Creation.Unix() {
				if err := pubkey.verifyUserAttrSelfSig(uat, sig); err == nil {
					uat.revSig = sig
					uat.RevSigDigest = sql.NullString{sig.ScopedDigest, true}
				}
			}
		}
	}
	for _, sig := range uat.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if time.Now().Unix() > sig.Expiration.Unix() {
			// Ignore expired signatures
			continue
		}
		if sig.SigType >= 0x10 && sig.SigType <= 0x13 {
			if err := pubkey.verifyUserAttrSelfSig(uat, sig); err == nil {
				if sig.Expiration.Unix() == NeverExpires.Unix() && sig.Signature != nil && sig.Signature.KeyLifetimeSecs != nil {
					sig.Expiration = pubkey.Creation.Add(
						time.Duration(*sig.Signature.KeyLifetimeSecs) * time.Second)
				}
				if uat.selfSignature == nil || sig.Creation.Unix() > uat.selfSignature.Creation.Unix() {
					uat.selfSignature = sig
				}
				if uat.revSig != nil && sig.Creation.Unix() > uat.selfSignature.Creation.Unix() {
					// A self-certification more recent than a revocation effectively cancels it.
					uat.revSig = nil
					uat.RevSigDigest = sql.NullString{"", false}
				}
			}
		}
	}
	// Flag User Attributes without a self-signature
	if uat.selfSignature == nil {
		uat.State |= PacketStateNoSelfSig
	}
}
