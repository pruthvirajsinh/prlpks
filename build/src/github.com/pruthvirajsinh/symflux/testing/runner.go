/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

// Package testing provides some unit-testing support functions.
package testing

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/bmizerany/assert"

	. "github.com/pruthvirajsinh/symflux"
	. "github.com/pruthvirajsinh/symflux/recon"
)

type PeerManager interface {
	CreatePeer() (*Peer, string)
	DestroyPeer(*Peer, string)
}

func runSockRecon(t *testing.T, peer1, peer2 *Peer, sock string) chan error {
	errChan := make(chan error, 2)
	l, err := net.Listen("unix", sock)
	assert.Equal(t, nil, err)
	go func() {
		defer l.Close()
		c1, err := l.Accept()
		assert.Equal(t, nil, err)
		err = peer1.Accept(c1)
		errChan <- err
	}()
	go func() {
		c2, err := net.Dial("unix", sock)
		assert.Equal(t, nil, err)
		err = peer2.InitiateRecon(c2)
		errChan <- err
	}()
	return errChan
}

func pollRootConvergence(t *testing.T, peer1, peer2 *Peer) chan error {
	errChan := make(chan error)
	go func() {
		timer := time.NewTimer(time.Duration(10) * time.Second)
		var zs1 *ZSet = NewZSet()
		var zs2 *ZSet = NewZSet()
	POLLING:
		for {
			select {
			case r1, ok := <-peer1.RecoverChan:
				if !ok {
					break POLLING
				}
				t.Logf("Peer1 recover: %v", r1)
				log.Println("Peer1 recover:", r1)
				for _, zp := range r1.RemoteElements {
					assert.T(t, zp != nil)
					peer1.Insert(zp)
				}
				peer1.ExecCmd(func() error {
					root1, err := peer1.Root()
					assert.Equal(t, err, nil)
					zs1 = NewZSet(root1.Elements()...)
					return err
				})
			case r2, ok := <-peer2.RecoverChan:
				if !ok {
					break POLLING
				}
				t.Logf("Peer2 recover: %v", r2)
				log.Println("Peer2 recover:", r2)
				for _, zp := range r2.RemoteElements {
					assert.T(t, zp != nil)
					peer2.Insert(zp)
				}
				peer2.ExecCmd(func() error {
					root2, err := peer2.Root()
					assert.Equal(t, err, nil)
					zs2 = NewZSet(root2.Elements()...)
					return err
				})
			case _ = <-timer.C:
				errChan <- fmt.Errorf("Timeout waiting for convergence")
				return
			}
			if zs1.Equal(zs2) {
				errChan <- nil
				return
			}
		}
		errChan <- fmt.Errorf("Set reconciliation did not converge")
	}()
	return errChan
}

func pollConvergence(t *testing.T, peer1, peer2 *Peer, peer1Needs, peer2Needs *ZSet, nsecs int) chan error {
	errChan := make(chan error)
	go func() {
		timer := time.NewTimer(time.Duration(nsecs) * time.Second)
	POLLING:
		for {
			select {
			case r1, ok := <-peer1.RecoverChan:
				if !ok {
					break POLLING
				}
				t.Logf("Peer1 recover: %v", r1)
				log.Println("Peer1 recover:", r1)
				for _, zp := range r1.RemoteElements {
					assert.T(t, zp != nil)
					peer1.Insert(zp)
					peer1Needs.Remove(zp)
				}
			case r2, ok := <-peer2.RecoverChan:
				if !ok {
					break POLLING
				}
				t.Logf("Peer2 recover: %v", r2)
				log.Println("Peer2 recover:", r2)
				for _, zp := range r2.RemoteElements {
					assert.T(t, zp != nil)
					peer2.Insert(zp)
					peer2Needs.Remove(zp)
				}
			case _ = <-timer.C:
				t.Log("TIMEOUT")
				t.Log("Peer1 still needs ", peer1Needs.Len(), ":", peer1Needs)
				t.Log("Peer2 still needs ", peer2Needs.Len(), ":", peer2Needs)
				errChan <- fmt.Errorf("Timeout waiting for convergence")
				return
			}
			if peer1Needs.Len() == 0 && peer2Needs.Len() == 0 {
				errChan <- nil
				return
			}
		}
		errChan <- fmt.Errorf("Set reconciliation did not converge")
	}()
	return errChan
}

func mksock(t *testing.T) string {
	var sock string
	{
		f, err := ioutil.TempFile("", "sock")
		assert.Equal(t, nil, err)
		defer f.Close()
		sock = f.Name()
	}
	assert.T(t, sock != "")
	err := os.Remove(sock)
	assert.Equal(t, nil, err)
	return sock
}

// Test full node sync.
func RunFullSync(t *testing.T, peerMgr PeerManager) {
	sock := mksock(t)
	defer os.Remove(sock)

	peer1, peer1Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer1, peer1Path)
	peer2, peer2Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer2, peer2Path)

	peer1.PrefixTree.Insert(Zi(P_SKS, 65537))
	peer1.PrefixTree.Insert(Zi(P_SKS, 65539))
	root, _ := peer1.PrefixTree.Root()
	log.Println("Peer1:", root.Elements())

	peer2.PrefixTree.Insert(Zi(P_SKS, 65537))
	peer2.PrefixTree.Insert(Zi(P_SKS, 65541))
	root, _ = peer2.PrefixTree.Root()
	log.Println("Peer2:", root.Elements())

	reconErrChan := runSockRecon(t, peer1, peer2, sock)
	convergeErrChan := pollRootConvergence(t, peer1, peer2)
	err := <-convergeErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
}

// Test sync with polynomial interpolation.
func RunPolySyncMBar(t *testing.T, peerMgr PeerManager) {
	sock := mksock(t)
	defer os.Remove(sock)

	peer1, peer1Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer1, peer1Path)
	peer2, peer2Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer2, peer2Path)

	onlyInPeer1 := NewZSet()
	// Load up peer 1 with items
	for i := 1; i < 100; i++ {
		peer1.PrefixTree.Insert(Zi(P_SKS, 65537*i))
	}
	// Four extra samples
	for i := 1; i < 5; i++ {
		z := Zi(P_SKS, 68111*i)
		peer1.PrefixTree.Insert(z)
		onlyInPeer1.Add(z)
	}
	root, _ := peer1.PrefixTree.Root()
	log.Println("Peer1:", root.Elements())

	onlyInPeer2 := NewZSet()
	// Load up peer 2 with items
	for i := 1; i < 100; i++ {
		peer2.PrefixTree.Insert(Zi(P_SKS, 65537*i))
	}
	// One extra sample
	for i := 1; i < 2; i++ {
		z := Zi(P_SKS, 70001*i)
		peer2.PrefixTree.Insert(z)
		onlyInPeer2.Add(z)
	}
	root, _ = peer2.PrefixTree.Root()
	log.Println("Peer2:", root.Elements())

	reconErrChan := runSockRecon(t, peer1, peer2, sock)
	convergeErrChan := pollConvergence(t, peer1, peer2, onlyInPeer2, onlyInPeer1, 10)
	err := <-convergeErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
}

// Test sync with polynomial interpolation.
func RunPolySyncLowMBar(t *testing.T, peerMgr PeerManager) {
	sock := mksock(t)
	defer os.Remove(sock)

	peer1, peer1Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer1, peer1Path)
	peer2, peer2Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer2, peer2Path)

	onlyInPeer1 := NewZSet()
	for i := 1; i < 100; i++ {
		peer1.PrefixTree.Insert(Zi(P_SKS, 65537*i))
	}
	// extra samples
	for i := 1; i < 50; i++ {
		z := Zi(P_SKS, 68111*i)
		onlyInPeer1.Add(z)
		peer1.PrefixTree.Insert(z)
	}
	root1, _ := peer1.PrefixTree.Root()
	log.Println("Peer1:", root1.Elements())

	onlyInPeer2 := NewZSet()
	for i := 1; i < 100; i++ {
		peer2.PrefixTree.Insert(Zi(P_SKS, 65537*i))
	}
	// extra samples
	for i := 1; i < 20; i++ {
		z := Zi(P_SKS, 70001*i)
		onlyInPeer2.Add(z)
		peer2.PrefixTree.Insert(z)
	}
	root2, _ := peer2.PrefixTree.Root()
	log.Println("Peer2:", root2.Elements())

	reconErrChan := runSockRecon(t, peer1, peer2, sock)
	convergeErrChan := pollConvergence(t, peer1, peer2, onlyInPeer2, onlyInPeer1, 10)
	err := <-convergeErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
}

// Test a one-sided sync
func RunOneSided(t *testing.T, peerMgr PeerManager, clientHas bool, n int, nsecs int) {
	sock := mksock(t)
	defer os.Remove(sock)

	peer1, peer1Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer1, peer1Path)
	peer2, peer2Path := peerMgr.CreatePeer()
	defer peerMgr.DestroyPeer(peer2, peer2Path)

	expected := NewZSet()
	var peer *Peer
	if clientHas {
		peer = peer2
	} else {
		peer = peer1
	}

	for i := 1; i < n; i++ {
		z := Zi(P_SKS, 65537*i)
		peer.PrefixTree.Insert(z)
		expected.Add(z)
	}

	var reconErrChan chan error
	reconErrChan = runSockRecon(t, peer1, peer2, sock)
	var convergeErrChan chan error
	if clientHas {
		convergeErrChan = pollConvergence(t, peer1, peer2, expected, NewZSet(), nsecs)
	} else {
		convergeErrChan = pollConvergence(t, peer1, peer2, NewZSet(), expected, nsecs)
	}
	err := <-convergeErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
	err = <-reconErrChan
	assert.Equal(t, nil, err)
	assert.Equal(t, 0, expected.Len())
}
