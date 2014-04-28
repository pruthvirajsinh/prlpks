/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package prlpks

import (
	"errors"
)

// Lookup key was not found in the database.
var ErrKeyNotFound = errors.New("Key not found.")

// An internal inconsistency between the stored key material and our indexing was detected.
var ErrInconsistentKey = errors.New("Stored key is internally inconsistent.")

// Key ID is invalid.
var ErrInvalidKeyId = errors.New("Invalid key ID.")

// Key hash is invalid.
var ErrInvalidKeyHash = errors.New("Invalid key hash.")

// A lookup with a short key ID found a collision.
// This is quite possible with short key IDs, remotely possibly with long IDs.
var ErrKeyIdCollision = errors.New("Key ID matches multiple public keys. Try again with a longer key ID.")

// A query resulted in more responses than we'd care to respond with.
var ErrTooManyResponses = errors.New("Too many responses.")

// Something was attempted that isn't fully baked yet.
var ErrUnsupportedOperation = errors.New("Unsupported operation.")

// Template path was not found. Installation or configuration problem.
var ErrTemplatePathNotFound = errors.New("Could not find templates. Check your installation and configuration.")
