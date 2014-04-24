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
	"database/sql"
	"io"
	"log"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp/packet"

	"github.com/pruthvirajsinh/prlpks/util"
)

type Subkey struct {
	RFingerprint string         `db:"uuid"`        // immutable
	Creation     time.Time      `db:"creation"`    // immutable
	Expiration   time.Time      `db:"expiration"`  // mutable
	State        int            `db:"state"`       // mutable
	Packet       []byte         `db:"packet"`      // immutable
	PubkeyRFP    string         `db:"pubkey_uuid"` // immutable
	RevSigDigest sql.NullString `db:"revsig_uuid"` // mutable
	Algorithm    int            `db:"algorithm"`   // immutable
	BitLen       int            `db:"bit_len"`     // immutable

	/* Containment references */

	signatures []*Signature `db:"-"`

	/* Cross-references */

	revSig     *Signature `db:"-"`
	bindingSig *Signature `db:"-"`

	/* Parsed packet data */

	PublicKey   *packet.PublicKey
	PublicKeyV3 *packet.PublicKeyV3
}

func (subkey *Subkey) Fingerprint() string {
	return util.Reverse(subkey.RFingerprint)
}

func (subkey *Subkey) KeyId() string {
	return util.Reverse(subkey.RFingerprint[:16])
}

func (subkey *Subkey) ShortId() string {
	return util.Reverse(subkey.RFingerprint[:8])
}

func (subkey *Subkey) Signatures() []*Signature { return subkey.signatures }

func (subkey *Subkey) Serialize(w io.Writer) error {
	_, err := w.Write(subkey.Packet)
	return err
}

func (subkey *Subkey) Uuid() string { return subkey.RFingerprint }

func (subkey *Subkey) GetOpaquePacket() (*packet.OpaquePacket, error) {
	return toOpaquePacket(subkey.Packet)
}

func (subkey *Subkey) GetPacket() (p packet.Packet, err error) {
	if subkey.PublicKey != nil {
		p = subkey.PublicKey
	} else if subkey.PublicKeyV3 != nil {
		p = subkey.PublicKeyV3
	} else {
		err = ErrPacketRecordState
	}
	return
}

func (subkey *Subkey) setPacket(p packet.Packet) (err error) {
	switch pk := p.(type) {
	case *packet.PublicKey:
		if !pk.IsSubkey {
			return ErrInvalidPacketType
		}
		subkey.PublicKey = pk
	case *packet.PublicKeyV3:
		if !pk.IsSubkey {
			return ErrInvalidPacketType
		}
		subkey.PublicKeyV3 = pk
	default:
		err = ErrInvalidPacketType
	}
	return
}

func (subkey *Subkey) Read() (err error) {
	buf := bytes.NewBuffer(subkey.Packet)
	var p packet.Packet
	if p, err = packet.Read(buf); err != nil {
		return err
	}
	return subkey.setPacket(p)
}

func NewSubkey(op *packet.OpaquePacket) (subkey *Subkey, err error) {
	var buf bytes.Buffer
	if err = op.Serialize(&buf); err != nil {
		return
	}
	subkey = &Subkey{Packet: buf.Bytes()}
	var p packet.Packet
	if p, err = op.Parse(); err != nil {
		return
	}
	if err = subkey.setPacket(p); err != nil {
		return
	}
	if subkey.PublicKey != nil {
		err = subkey.initV4()
	} else if subkey.PublicKeyV3 != nil {
		err = subkey.initV3()
	} else {
		err = ErrInvalidPacketType
	}
	return
}

func (subkey *Subkey) initV4() error {
	fingerprint := Fingerprint(subkey.PublicKey)
	bitLen, err := subkey.PublicKey.BitLength()
	if err != nil {
		return err
	}
	if !subkey.PublicKey.IsSubkey {
		log.Println("Expected sub-key packet, got primary public key")
		return ErrInvalidPacketType
	}
	subkey.RFingerprint = util.Reverse(fingerprint)
	subkey.Creation = subkey.PublicKey.CreationTime
	subkey.Expiration = NeverExpires
	subkey.Algorithm = int(subkey.PublicKey.PubKeyAlgo)
	subkey.BitLen = int(bitLen)
	return nil
}

func (subkey *Subkey) initV3() error {
	fingerprint := FingerprintV3(subkey.PublicKeyV3)
	bitLen, err := subkey.PublicKeyV3.BitLength()
	if err != nil {
		return err
	}
	if subkey.PublicKeyV3.IsSubkey {
		log.Println("Expected primary public key packet, got sub-key")
		return ErrInvalidPacketType
	}
	subkey.RFingerprint = util.Reverse(fingerprint)
	subkey.Creation = subkey.PublicKeyV3.CreationTime
	subkey.Expiration = NeverExpires
	if subkey.PublicKeyV3.DaysToExpire > 0 {
		subkey.Expiration = subkey.Creation.Add(time.Duration(subkey.PublicKeyV3.DaysToExpire) * time.Hour * 24)
	}
	subkey.Algorithm = int(subkey.PublicKeyV3.PubKeyAlgo)
	subkey.BitLen = int(bitLen)
	return nil
}

func (subkey *Subkey) Visit(visitor PacketVisitor) (err error) {
	err = visitor(subkey)
	if err != nil {
		return
	}
	for _, sig := range subkey.signatures {
		err = sig.Visit(visitor)
		if err != nil {
			return
		}
	}
	return
}

func (subkey *Subkey) AddSignature(sig *Signature) {
	subkey.signatures = append(subkey.signatures, sig)
}

func (subkey *Subkey) RemoveSignature(sig *Signature) {
	subkey.signatures = removeSignature(subkey.signatures, sig)
}

func (subkey *Subkey) linkSelfSigs(pubkey *Pubkey) {
	for _, sig := range subkey.signatures {
		if !strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) {
			continue
		}
		if sig.SigType == 0x20 { // TODO: add packet.SigTypeKeyRevocation
			// Use the earliest valid revocation of this key
			if subkey.revSig == nil || sig.Creation.Unix() < subkey.revSig.Creation.Unix() {
				if err := pubkey.verifyPublicKeySelfSig(subkey, sig); err == nil {
					subkey.revSig = sig
					subkey.RevSigDigest = sql.NullString{sig.ScopedDigest, true}
				}
			}
		} else if sig.SigType == 0x18 && time.Now().Unix() < sig.Expiration.Unix() { // TODO: add packet.SigTypeSubkeyBinding
			if err := pubkey.verifyPublicKeySelfSig(subkey, sig); err == nil {
				if sig.Expiration.Unix() == NeverExpires.Unix() && sig.Signature != nil && sig.Signature.KeyLifetimeSecs != nil {
					sig.Expiration = subkey.Creation.Add(
						time.Duration(*sig.Signature.KeyLifetimeSecs) * time.Second)
				}
				if subkey.bindingSig == nil || sig.Creation.Unix() < subkey.bindingSig.Creation.Unix() {
					subkey.bindingSig = sig
					subkey.PubkeyRFP = pubkey.RFingerprint
				}
			}
		}
	}
	// Remove subkeys without a binding signature
	if subkey.bindingSig == nil {
		subkey.State |= PacketStateNoBindingSig
	}
}

func (subkey *Subkey) publicKey() *packet.PublicKey     { return subkey.PublicKey }
func (subkey *Subkey) publicKeyV3() *packet.PublicKeyV3 { return subkey.PublicKeyV3 }
