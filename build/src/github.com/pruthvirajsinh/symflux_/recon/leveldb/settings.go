/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package leveldb

import (
	"github.com/pruthvirajsinh/symflux/recon"
)

type Settings struct {
	*recon.Settings
}

func (s *Settings) Path() string {
	return s.GetString("symflux.recon.leveldb.path", "symflux-ptree")
}

func NewSettings(reconSettings *recon.Settings) *Settings {
	return &Settings{reconSettings}
}

func DefaultSettings() *Settings {
	return NewSettings(recon.DefaultSettings())
}
