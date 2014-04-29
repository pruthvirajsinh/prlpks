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
	"testing"

	/*
		"net/http"
		"log"
		_ "net/http/pprof"
	*/

	"github.com/pruthvirajsinh/symflux/recon"
	. "github.com/pruthvirajsinh/symflux/testing"
)

/*
func init() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}
*/

type peerManager struct {
	t *testing.T
}

func (lpm *peerManager) CreatePeer() (peer *recon.Peer, path string) {
	return createTestPeer(lpm.t), ""
}

func (lpm *peerManager) DestroyPeer(peer *recon.Peer, path string) {
	destroyTestPeer(peer)
}

// Test full node sync.
func TestFullSync(t *testing.T) {
	RunFullSync(t, &peerManager{t})
}

// Test sync with polynomial interpolation.
func TestPolySyncMBar(t *testing.T) {
	RunPolySyncMBar(t, &peerManager{t})
}

// Test sync with polynomial interpolation.
func TestPolySyncLowMBar(t *testing.T) {
	RunPolySyncLowMBar(t, &peerManager{t})
}

func TestOneSidedMediumLeft(t *testing.T) {
	RunOneSided(t, &peerManager{t}, false, 250, 10)
}

func TestOneSidedMediumRight(t *testing.T) {
	RunOneSided(t, &peerManager{t}, true, 250, 10)
}

func TestOneSidedLarge(t *testing.T) {
	RunOneSided(t, &peerManager{t}, false, 15000, 180)
	RunOneSided(t, &peerManager{t}, true, 15000, 180)
}

func TestSplits85(t *testing.T) {
	RunSplits85(t, &peerManager{t})
}

func TestSplits15k(t *testing.T) {
	RunSplits15k(t, &peerManager{t})
}
