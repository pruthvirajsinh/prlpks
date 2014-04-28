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
	"sort"
	"strings"
)

type uidSorter struct {
	*Pubkey
}

func (s *uidSorter) Len() int { return len(s.userIds) }

func (s *uidSorter) Less(i, j int) bool {
	iSig := maxSelfSig(s.Pubkey, s.userIds[i].signatures)
	jSig := maxSelfSig(s.Pubkey, s.userIds[j].signatures)
	return sigLess(iSig, jSig)
}

func sigLess(iSig *Signature, jSig *Signature) bool {
	if iSig != nil && jSig != nil {
		if iSig.IsPrimary() != jSig.IsPrimary() {
			return iSig.IsPrimary()
		}
		return iSig.Creation.Unix() > jSig.Creation.Unix()
	}
	return iSig != nil
}

func maxSelfSig(pubkey *Pubkey, sigs []*Signature) (recent *Signature) {
	for _, sig := range sigs {
		if strings.HasPrefix(pubkey.RFingerprint, sig.RIssuerKeyId) && (recent == nil || sig.Creation.Unix() > recent.Creation.Unix()) {
			recent = sig
		}
	}
	return
}

func (s *uidSorter) Swap(i, j int) {
	s.userIds[i], s.userIds[j] = s.userIds[j], s.userIds[i]
}

type uatSorter struct {
	*Pubkey
}

func (s *uatSorter) Len() int { return len(s.userAttributes) }

func (s *uatSorter) Less(i, j int) bool {
	iSig := maxSelfSig(s.Pubkey, s.userAttributes[i].signatures)
	jSig := maxSelfSig(s.Pubkey, s.userAttributes[j].signatures)
	return sigLess(iSig, jSig)
}

func (s *uatSorter) Swap(i, j int) {
	s.userAttributes[i], s.userAttributes[j] = s.userAttributes[j], s.userAttributes[i]
}

type subkeySorter struct {
	*Pubkey
}

func (s *subkeySorter) Len() int { return len(s.subkeys) }

func (s *subkeySorter) Less(i, j int) bool {
	if (s.subkeys[i].revSig == nil) != (s.subkeys[j].revSig == nil) {
		return s.subkeys[i].revSig != nil
	}
	return s.subkeys[i].Creation.Unix() < s.subkeys[j].Creation.Unix()
}

func (s *subkeySorter) Swap(i, j int) {
	s.subkeys[i], s.subkeys[j] = s.subkeys[j], s.subkeys[i]
}

type sigSorter struct {
	sigs []*Signature
}

func (s *sigSorter) Len() int { return len(s.sigs) }

func (s *sigSorter) Less(i, j int) bool {
	return s.sigs[i].Creation.Unix() < s.sigs[j].Creation.Unix()
}

func (s *sigSorter) Swap(i, j int) {
	s.sigs[i], s.sigs[j] = s.sigs[j], s.sigs[i]
}

// Sort reorders the key material
func Sort(pubkey *Pubkey) {
	pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *UserId:
			sort.Sort(&sigSorter{r.signatures})
		case *UserAttribute:
			sort.Sort(&sigSorter{r.signatures})
		case *Subkey:
			sort.Sort(&sigSorter{r.signatures})
		}
		return nil
	})
	sort.Sort(&uidSorter{pubkey})
	sort.Sort(&uatSorter{pubkey})
	sort.Sort(&subkeySorter{pubkey})
}
