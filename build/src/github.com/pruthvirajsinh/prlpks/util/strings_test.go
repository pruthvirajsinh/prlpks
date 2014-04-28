/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package util

import (
	"testing"

	"github.com/bmizerany/assert"
)

func TestUserIdRegex(t *testing.T) {
	// Name, comment, email address
	matches := UserIdRegex.FindStringSubmatch("Alice Practice (Crystal Castles) <alice.practice@example.com>")
	assert.Equal(t, matches[1], "Alice Practice")
	assert.Equal(t, matches[2], "(Crystal Castles)")
	assert.Equal(t, matches[3], "<alice.practice@example.com>")
	// Name only
	matches = UserIdRegex.FindStringSubmatch("John E. Smoke")
	assert.Equal(t, matches[1], "John E. Smoke")
	// Name and comment
	matches = UserIdRegex.FindStringSubmatch("John E. Smoke (John W. Smoke)")
	assert.Equal(t, matches[1], "John E. Smoke")
	assert.Equal(t, matches[2], "(John W. Smoke)")
	// Name and email address
	matches = UserIdRegex.FindStringSubmatch("John E. Smoke <theflameitself@example.com>")
	assert.Equal(t, matches[1], "John E. Smoke")
	assert.Equal(t, matches[3], "<theflameitself@example.com>")
	// Email address only
	matches = UserIdRegex.FindStringSubmatch("<noname@example.com>")
	assert.Equal(t, matches[3], "<noname@example.com>")
	// Without angle brackets, could be a name
	matches = UserIdRegex.FindStringSubmatch("noname@example.com")
	assert.Equal(t, matches[1], "noname@example.com")
	// Wat.
	matches = UserIdRegex.FindStringSubmatch(`o      \     \______// _ ___ _ (_(__>  \   |    o`)
	// Don't die
	assert.T(t, len(matches) > 0)
	// Name has parens
	matches = UserIdRegex.FindStringSubmatch("T(A)ILS developers (signing key) <amnesia@boum.org>")
	assert.Equal(t, matches[1], "T(A)ILS developers")
}

func TestSplitUserId(t *testing.T) {
	keywords := SplitUserId("Alice Practice (Crystal Castles) <alice.practice@example.com>")
	assert.Equal(t, "alice practice", keywords[0])
	assert.Equal(t, "crystal castles", keywords[1])
	assert.Equal(t, "alice.practice@example.com", keywords[2])
	// drop short words
	keywords = SplitUserId("John W. Smoke <JOHNNYSMOKE@example.com>")
	assert.Equal(t, "john smoke", keywords[0])
	// lowercase email addresses too
	assert.Equal(t, "johnnysmoke@example.com", keywords[1])
	// search queries
	keywords = SplitUserId("john smoke")
	assert.Equal(t, "john smoke", keywords[0])
	keywords = SplitUserId("johnwsmoke@example.com")
	assert.Equal(t, "johnwsmoke example com", keywords[0])
}
