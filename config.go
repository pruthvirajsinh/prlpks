/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// Package prlpks provides common configuration, logging and
// static content for the keyserver.
package prlpks

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/pelletier/go-toml"
)

var config *Settings

// Config returns the global Settings for an application built with prlpks.
func Config() *Settings {
	return config
}

// Settings stores configuration options for prlpks.
type Settings struct {
	*toml.TomlTree
}

// GetString returns the string value for the configuration key if set,
// otherwise the empty string.
func (s *Settings) GetString(key string) string {
	return s.GetStringDefault(key, "")
}

// GetStringDefault returns the string value for the configuration key if set,
// otherwise the default value.
func (s *Settings) GetStringDefault(key string, defaultValue string) string {
	if s, is := s.Get(key).(string); is {
		return s
	}
	return defaultValue
}

// MustGetInt returns the int value for the configuration key if set and valid,
// otherwise panics.
func (s *Settings) MustGetInt(key string) int {
	if v, err := s.getInt(key); err == nil {
		return v
	} else {
		panic(err)
	}
}

// GetIntDefault returns the int value for the configuration key if set and valid,
// otherwise the default value.
func (s *Settings) GetIntDefault(key string, defaultValue int) int {
	if v, err := s.getInt(key); err == nil {
		return v
	} else {
		return defaultValue
	}
}

func (s *Settings) getInt(key string) (int, error) {
	switch v := s.Get(key).(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	default:
		if i, err := strconv.Atoi(fmt.Sprintf("%v", v)); err != nil {
			return 0, err
		} else {
			s.Set(key, i)
			return i, nil
		}
	}
	panic("unreachable")
}

// GetBool returns the boolean value for the configuration key if set,
// otherwise false.
func (s *Settings) GetBool(key string) bool {
	var result bool
	switch v := s.Get(key).(type) {
	case bool:
		return v
	case int:
		result = v != 0
	case string:
		b, err := strconv.ParseBool(v)
		result = err == nil && b
	default:
		result = false
	}
	s.Set(key, result)
	return result
}

// GetStrings returns a []string slice for the configuration key if set,
// otherwise an empty slice.
func (s *Settings) GetStrings(key string) (value []string) {
	if strs, is := s.Get(key).([]interface{}); is {
		for _, v := range strs {
			if str, is := v.(string); is {
				value = append(value, str)
			}
		}
	}
	return
}

// SetConfig sets the global configuration to the TOML-formatted string contents.
func SetConfig(contents string) (err error) {
	var tree *toml.TomlTree
	if tree, err = toml.Load(contents); err != nil {
		return
	}
	config = &Settings{tree}
	return
}

// LoadConfig sets the global configuration to the TOML-formatted reader contents.
func LoadConfig(r io.Reader) (err error) {
	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, r)
	if err != nil {
		return
	}
	var tree *toml.TomlTree
	if tree, err = toml.Load(buf.String()); err != nil {
		return
	}
	config = &Settings{tree}
	return
}

// LoadConfigFile sets the global configuration to the contents from the TOML file path.
func LoadConfigFile(path string) (err error) {
	var tree *toml.TomlTree
	if tree, err = toml.LoadFile(path); err != nil {
		return
	}
	config = &Settings{tree}
	return
}
