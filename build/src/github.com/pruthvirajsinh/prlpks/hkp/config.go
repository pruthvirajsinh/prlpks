/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// Package hkp implements the OpenPGP HTTP Keyserver Protocol, as
// described in the Internet-Draft, http://ietfreport.isoc.org/idref/draft-shaw-openpgp-hkp/.
//
// hkp provides a few extensions to the protocol, such as
// SKS hashquery, server statistics and JSON-formatted search results.
package hkp

import (
	"github.com/pruthvirajsinh/prlpks"
)

// Settings stores HKP-specific settings for prlpks.
type Settings struct {
	*prlpks.Settings
}

// Config returns the global HKP-specific Settings for prlpks.
func Config() *Settings {
	return &Settings{prlpks.Config()}
}
