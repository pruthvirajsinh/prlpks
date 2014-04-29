/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// Package recon provides the SKS reconciliation protocol, prefix tree interface
// and an in-memory prefix-tree implementation.
package recon

import (
	"bytes"
	"fmt"
	"github.com/pelletier/go-toml"
	"net"
	"strconv"
	"strings"
)

type Settings struct {
	*toml.TomlTree
	splitThreshold int
	joinThreshold  int
	numSamples     int
}

func (s *Settings) GetString(key string, defaultValue string) string {
	if s, is := s.GetDefault(key, defaultValue).(string); is {
		return s
	}
	return defaultValue
}

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

func (s *Settings) GetInt(key string, defaultValue int) int {
	switch v := s.GetDefault(key, defaultValue).(type) {
	case int:
		return v
	case int64:
		return int(v)
	default:
		i, err := strconv.Atoi(fmt.Sprintf("%v", v))
		if err != nil {
			panic(err)
		}
		s.Set(key, i)
		return i
	}
	return defaultValue
}

func (s *Settings) Version() string {
	return s.GetString("symflux.recon.version", "1.1.3")
}

func (s *Settings) LogName() string {
	return s.GetString("symflux.recon.logname", "symflux.recon")
}

func (s *Settings) HttpPort() int {
	return s.GetInt("symflux.recon.httpPort", 11371)
}

func (s *Settings) ReconPort() int {
	return s.GetInt("symflux.recon.reconPort", 11370)
}

func (s *Settings) Partners() []string {
	return s.GetStrings("symflux.recon.partners")
}

func (s *Settings) Filters() []string {
	return s.GetStrings("symflux.recon.filters")
}

func (s *Settings) ThreshMult() int {
	return s.GetInt("symflux.recon.threshMult", DefaultThreshMult)
}

func (s *Settings) BitQuantum() int {
	return s.GetInt("symflux.recon.bitQuantum", DefaultBitQuantum)
}

func (s *Settings) MBar() int {
	return s.GetInt("symflux.recon.mBar", DefaultMBar)
}

func (s *Settings) SplitThreshold() int {
	return s.splitThreshold
}

func (s *Settings) JoinThreshold() int {
	return s.joinThreshold
}

func (s *Settings) NumSamples() int {
	return s.numSamples
}

func (s *Settings) GossipIntervalSecs() int {
	return s.GetInt("symflux.recon.gossipIntervalSecs", 60)
}

func (s *Settings) MaxOutstandingReconRequests() int {
	return s.GetInt("symflux.recon.maxOutstandingReconRequests", 100)
}

func (s *Settings) ConnTimeout() int {
	return s.GetInt("symflux.recon.connTimeout", 0)
}

func (s *Settings) ReadTimeout() int {
	return s.GetInt("symflux.recon.readTimeout", 0)
}

func DefaultSettings() (settings *Settings) {
	buf := bytes.NewBuffer(nil)
	var tree *toml.TomlTree
	var err error
	if tree, err = toml.Load(buf.String()); err != nil {
		panic(err) // unlikely
	}
	return NewSettings(tree)
}

func NewSettings(tree *toml.TomlTree) (settings *Settings) {
	settings = &Settings{tree, DefaultSplitThreshold, DefaultJoinThreshold, DefaultNumSamples}
	settings.UpdateDerived()
	return
}

func (s *Settings) Config() *Config {
	return &Config{
		Version:    s.Version(),
		HttpPort:   s.HttpPort(),
		BitQuantum: s.BitQuantum(),
		MBar:       s.MBar(),
		Filters:    strings.Join(s.Filters(), ",")}
}

func (s *Settings) UpdateDerived() {
	s.splitThreshold = s.ThreshMult() * s.MBar()
	s.joinThreshold = s.splitThreshold / 2
	s.numSamples = s.MBar() + 1
}

func LoadSettings(path string) (*Settings, error) {
	var tree *toml.TomlTree
	var err error
	if tree, err = toml.LoadFile(path); err != nil {
		return nil, err
	}
	return NewSettings(tree), nil
}

func (s *Settings) PartnerAddrs() (addrs []net.Addr, err error) {
	for _, partner := range s.Partners() {
		if partner == "" {
			continue
		}
		addr, err := net.ResolveTCPAddr("tcp", partner)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return
}
