/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// Package openpgp parses, merges, validates, stores and searches OpenPGP public key material in RFC4880 format. Workers handle HKP requests, process their contents, and produce HKP responses.
//
// Public key material is stored in a PostgreSQL database.
package openpgp
