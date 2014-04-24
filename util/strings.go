/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// Package util contains a few commonly used utility functions.
package util

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MIN_KEYWORD_LEN = 3

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

var UserIdRegex *regexp.Regexp = regexp.MustCompile(`^\s*(\S.*\b)?\s*(\([^(]+\))?\s*(<[^>]+>)?$`)

func isUserDelim(c rune) bool {
	return !unicode.IsLetter(c) && !unicode.IsDigit(c)
}

// Split a user ID string into fulltext searchable keywords.
func SplitUserId(id string) (keywords []string) {
	matches := UserIdRegex.FindStringSubmatch(id)
	if len(matches) > 1 {
		match := keywordNormalize(matches[1])
		if len(match) >= MIN_KEYWORD_LEN {
			keywords = append(keywords, match)
		}
	}
	if len(matches) > 2 {
		match := keywordNormalize(strings.Trim(matches[2], "()"))
		if len(match) >= MIN_KEYWORD_LEN {
			keywords = append(keywords, match)
		}
	}
	if len(matches) > 3 {
		match := strings.ToLower(strings.Trim(matches[3], "<>"))
		if len(match) >= MIN_KEYWORD_LEN {
			keywords = append(keywords, match)
		}
	}
	return keywords
}

func keywordNormalize(s string) string {
	var fields []string
	for _, s := range strings.FieldsFunc(s, isUserDelim) {
		s = strings.ToLower(strings.TrimFunc(s, isUserDelim))
		if len(s) > 2 {
			fields = append(fields, s)
		}
	}
	return strings.Join(fields, " ")
}

func CleanUtf8(s string) string {
	var runes []rune
	for _, r := range s {
		if r == utf8.RuneError {
			r = '?'
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		runes = append(runes, r)
	}
	return string(runes)
}
