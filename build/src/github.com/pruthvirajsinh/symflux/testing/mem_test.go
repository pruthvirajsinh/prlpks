/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package testing

import (
	. "github.com/pruthvirajsinh/symflux/recon"
	"os"
	"testing"
)

type memPeerManager struct{}

func (mpm *memPeerManager) CreatePeer() (peer *Peer, path string) {
	peer = NewMemPeer()
	go peer.HandleCmds()
	return peer, ""
}

func (mpm *memPeerManager) DestroyPeer(peer *Peer, path string) {
	if peer != nil {
		peer.Stop()
	}
	if path != "" {
		os.RemoveAll(path)
	}
}

var memPeerMgr *memPeerManager = &memPeerManager{}

// Test full node sync.
func TestFullSync(t *testing.T) {
	RunFullSync(t, memPeerMgr)
}

// Test sync with polynomial interpolation.
func TestPolySyncMBar(t *testing.T) {
	RunPolySyncMBar(t, memPeerMgr)
}

// Test sync with polynomial interpolation.
func TestPolySyncLowMBar(t *testing.T) {
	RunPolySyncLowMBar(t, memPeerMgr)
}

func TestOneSidedMedium(t *testing.T) {
	RunOneSided(t, memPeerMgr, false, 250, 30)
	RunOneSided(t, memPeerMgr, true, 250, 30)
}

func TestOneSidedLarge(t *testing.T) {
	RunOneSided(t, memPeerMgr, false, 15000, 60)
	RunOneSided(t, memPeerMgr, true, 15000, 60)
}

func TestOneSidedRidiculous(t *testing.T) {
	RunOneSided(t, memPeerMgr, false, 150000, 180)
	RunOneSided(t, memPeerMgr, true, 150000, 180)
}

func TestSplits85(t *testing.T) {
	RunSplits85(t, memPeerMgr)
}

func TestSplits15k(t *testing.T) {
	RunSplits15k(t, memPeerMgr)
}
