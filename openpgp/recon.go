/*

PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

//Made Changes to be in sync with https://github.com/cmars/hockeypuck/commit/80151d7026c3225178f24151386ce871223669e2
package openpgp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	. "github.com/pruthvirajsinh/symflux"
	"github.com/pruthvirajsinh/symflux/recon"
	"github.com/pruthvirajsinh/symflux/recon/leveldb"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	//	"github.com/pruthvirajsinh/PrcIdSigner"
	"github.com/pruthvirajsinh/prlpks/hkp"
)

type SksPeer struct {
	*recon.Peer
	Service        *hkp.Service
	RecoverKey     chan *RecoverKey
	KeyChanges     KeyChangeChan
	LocalDeleteKey chan *LocalDeleteKey
}

type RecoverKey struct {
	Keytext []byte
	//RecoverSet *ZSet
	Source   string
	response hkp.ResponseChan
	//PRC Start
	verifiedDomains []string
	//PRC End
}

func NewSksPTree(reconSettings *recon.Settings) (recon.PrefixTree, error) {
	treeSettings := leveldb.NewSettings(reconSettings)
	return leveldb.New(treeSettings)
}

func NewSksPeer(s *hkp.Service) (*SksPeer, error) {
	reconSettings := recon.NewSettings(Config().Settings.TomlTree)
	ptree, err := NewSksPTree(reconSettings)
	if err != nil {
		return nil, err
	}
	//tmpAuth := recon.Authority{"dummy.com", "admin@dummy.com", "no key"}
	peer := recon.NewPeer(reconSettings, ptree)
	sksPeer := &SksPeer{
		Peer:           peer,
		Service:        s,
		KeyChanges:     make(KeyChangeChan, reconSettings.SplitThreshold()),
		RecoverKey:     make(chan *RecoverKey),
		LocalDeleteKey: make(chan *LocalDeleteKey)}
	return sksPeer, nil
}

func (r *SksPeer) Start() {
	r.Peer.PrefixTree.Create()

	//Added from latest hockeypuck,cleanly close the peer so that tree will be in consistent state.
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)
	go func() {
		select {
		case sig := <-sigChan:
			log.Printf("captured %v, at %s stopping Peer..", sig, time.Now())
			fmt.Printf("\nWarning!! Captured %v, at %s stopping Peer..\n", sig, time.Now())
			r.Peer.Stop()
		}
	}()

	//PRC Start
	if UpdateOwnLocalState() != nil {
		fmt.Println("Error updating Own Local State")
		log.Println("Error updating Own Local State")
	}
	//PRC End
	go r.HandleRecovery()
	go r.HandleKeyUpdates()
	go r.Peer.Start()
}

func (r *SksPeer) HandleKeyUpdates() {
	for {

		select {
		case keyChange, ok := <-r.KeyChanges:
			if !ok {
				return
			}

			digest, err := hex.DecodeString(keyChange.CurrentMd5)
			if err != nil {
				log.Println("bad digest:", keyChange.CurrentMd5)
				continue
			}
			digest = recon.PadSksElement(digest)
			digestZp := Zb(P_SKS, digest)
			//PRC START
			//Handle Key Delete
			//remove node from ptree
			if keyChange.Type == KeyDeleted {
				log.Println("MD5:", keyChange.CurrentMd5)
				log.Println("Prefix Tree: Remove:", digestZp)
				err = r.Peer.Remove(digestZp)
				if err != nil {
					log.Println(err)
					continue
				}
				fmt.Print("-")

				//PRC END
			} else {
				//Before else if keyChange.PreviousMd5 != keyChange.CurrentMd5
				//Changed according to latest hockeypuck,issue insert without checking for change,
				//The ptree will itself not add duplicate elements.
				log.Println("Prefix tree: Insert:", hex.EncodeToString(digestZp.Bytes()), keyChange, keyChange.CurrentMd5)
				err := r.Peer.Insert(digestZp)
				if err != nil {
					log.Println(err)
					continue
				}
				fmt.Print("+")

				if keyChange.PreviousMd5 != "" && keyChange.PreviousMd5 != keyChange.CurrentMd5 {
					prevDigest, err := hex.DecodeString(keyChange.PreviousMd5)
					if err != nil {
						log.Println("bad digest:", keyChange.PreviousMd5)
						continue
					}
					prevDigest = recon.PadSksElement(prevDigest)
					prevDigestZp := Zb(P_SKS, prevDigest)
					log.Println("Prefix Tree: Remove:", prevDigestZp)
					err = r.Peer.Remove(prevDigestZp)
					if err != nil {
						log.Println(err)
						continue
					}
					fmt.Print("-")

				}
			}
			//PRC Start
			//errOwn := UpdateOwnLocalState()
			//if errOwn != nil {
			//	fmt.Println("Error updating Own Local State")
			//	log.Println("Error updating Own Local State")
			//}
			//PRC End

		}

	}
}

func (r *SksPeer) HandleRecovery() {
	fmt.Println("Handling Recovery")
	rcvrChans := make(map[string]chan *recon.Recover)

	defer func() {
		for _, ch := range rcvrChans {
			close(ch)
		}
	}()
	for {
		select {
		case rcvr, ok := <-r.Peer.RecoverChan:
			if !ok {
				return
			}

			// Use remote HKP host:port as peer-unique identifier
			remoteAddr, err := rcvr.HkpAddr()
			if err != nil {
				continue
			}
			// Mux recoveries to per-address channels
			rcvrChan, has := rcvrChans[remoteAddr]
			if !has {
				rcvrChan = make(chan *recon.Recover)
				rcvrChans[remoteAddr] = rcvrChan

				go r.handleRemoteRecovery(rcvr, rcvrChan)
				//PRC Start
				//go r.handleLocalDifference(rcvr, rcvrChan)
				//PRC End
			}
			rcvrChan <- rcvr
		}
	}
}

type reconSets struct {
	recovered *ZSet
	localDiff *ZSet
}
type workRecoveredReady chan interface{}
type workRecoveredWork chan reconSets

func (r *SksPeer) handleRemoteRecovery(rcvr *recon.Recover, rcvrChan chan *recon.Recover) {

	//Stat End

	recovered := NewZSet()
	//PRC Start
	localDiff := NewZSet()
	//PRC End
	ready := make(workRecoveredReady)
	work := make(workRecoveredWork)

	defer close(work)

	go r.workRecovered(rcvr, ready, work)

	for {
		select {
		case rcvr, ok := <-rcvrChan:
			if !ok {
				return
			}
			// Aggregate recovered IDs
			recovered.AddSlice(rcvr.RemoteElements)
			localDiff.AddSlice(rcvr.LocalElements)
			fmt.Println("Recon.go: Peer(", rcvr.RemoteAddr.String(), ") has = ", len(recovered.Items()), " , I have = ", len(localDiff.Items()))
			log.Println("Recovery from", rcvr.RemoteAddr.String(), ":", recovered.Len(), "pending")
			r.Peer.Pause()
		case _, ok := <-ready:
			// Recovery worker is ready for more
			if !ok {
				return
			}
			work <- reconSets{recovered: recovered, localDiff: localDiff}
			recovered = NewZSet()
			localDiff = NewZSet()
		}
	}
}

func (r *SksPeer) workRecovered(rcvr *recon.Recover, ready workRecoveredReady, work workRecoveredWork) {
	defer close(ready)
	timer := time.NewTimer(time.Duration(3) * time.Second)
	defer timer.Stop()
	//PRC Start
	fmt.Println("Working Recovered")
	remoteAddr, err := rcvr.HkpAddr()
	if err != nil {
		return
	}

	for {
		select {
		case reconedSet, ok := <-work:
			if !ok {
				return
			}

			rcvr.RemoteAllStatesJSON, err = ReconGetRemoteStates(remoteAddr)
			if err != nil {
				fmt.Println("Cant get JSON , err: ", err)
				continue
			}

			err = r.deleteLocal(rcvr, reconedSet.localDiff)
			if err != nil {
				log.Println(err)
				fmt.Println("DeleteLOcal Returned:", err)
			}
			err = r.requestRecovered(rcvr, reconedSet.recovered)
			if err != nil {
				log.Println(err)
				fmt.Println("RequestRecovered Returned:", err)
			}

			fmt.Println("!")
			remoteStates, errRe := GetStatesFromJSON(rcvr.RemoteAllStatesJSON)
			if errRe != nil {
				fmt.Println("Error While json to states of ", remoteAddr)
			} else {
				errMerge := MergeStatesInToLocal(remoteStates, rcvr.RemoteAllStatesJSON)
				if errMerge != nil {
					fmt.Println("Error While merging remote States of ", remoteAddr, " err:", errMerge)
				}
				//PRC End
			}

			errOwn := UpdateOwnLocalState()
			if errOwn != nil {
				fmt.Println("Error updating Own Local State")
				log.Println("Error updating Own Local State")
			}
			//PRC End
			timer.Reset(time.Duration(r.Peer.GossipIntervalSecs()) * time.Second)
			r.Peer.Resume()
		case <-timer.C:
			timer.Stop()
			ready <- new(interface{})
		}
	}
}

const RequestChunkSize = 100

func (r *SksPeer) requestRecovered(rcvr *recon.Recover, elements *ZSet) (err error) {
	items := elements.Items()
	for len(items) > 0 {
		// Chunk requests to keep the hashquery message size and peer load reasonable.
		chunksize := RequestChunkSize
		if chunksize > len(items) {
			chunksize = len(items)
		}
		chunk := items[:chunksize]
		items = items[chunksize:]
		err = r.requestChunk(rcvr, chunk)
		if err != nil {
			log.Println(err)
		}
	}
	return
}

func (r *SksPeer) requestChunk(rcvr *recon.Recover, chunk []*Zp) (err error) {
	//Get MappedDomains for authenticatioon of add
	defer fmt.Println("Error While Returning from requestRecoverd", err)
	verifiedDomains, errM := RecoveryAuthentication(rcvr.RemoteAllStatesJSON)
	if errM != nil {
		return
	}
	fmt.Println("requestRecovered", verifiedDomains)

	var remoteAddr string
	remoteAddr, err = rcvr.HkpAddr()
	if err != nil {
		return err
	}
	// Make an sks hashquery request
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(chunk))
	if err != nil {
		return err
	}
	for _, z := range chunk {
		zb := z.Bytes()
		zb = recon.PadSksElement(zb)
		// Hashquery elements are 16 bytes (length_of(P_SKS)-1)
		zb = zb[:len(zb)-1]
		err = recon.WriteInt(hqBuf, len(zb))
		if err != nil {
			return err
		}
		_, err = hqBuf.Write(zb)
		if err != nil {
			return err
		}
	}

	//if len(hqBuf.Bytes()) == 0 {
	//	return
	//}
	fmt.Println("Sending Hashquerry to ", remoteAddr, " for md5uuid= ", string(hqBuf.Bytes()))
	resp, err1 := http.Post(fmt.Sprintf("http://%s/pks/hashquery", remoteAddr),
		"sks/hashquery", bytes.NewReader(hqBuf.Bytes()))
	if err1 != nil {
		err = err1
		return
	}

	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	{
		defer resp.Body.Close()
		bodyBuf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(bodyBuf)
	}
	var nkeys, keyLen int
	nkeys, err = recon.ReadInt(body)
	if err != nil {
		return err
	}
	log.Println("Response from server:", nkeys, " keys found")
	fmt.Println("Response from server:", nkeys, " keys found")

	for i := 0; i < nkeys; i++ {
		keyLen, err = recon.ReadInt(body)
		if err != nil {
			return err
		}
		keyBuf := bytes.NewBuffer(nil)
		_, err = io.CopyN(keyBuf, body, int64(keyLen))
		if err != nil {
			return err
		}
		log.Println("Key#", i+1, ":", keyLen, "bytes")
		// Merge locally

		recoverKey := &RecoverKey{
			Keytext: keyBuf.Bytes(),
			//RecoverSet:      elements,
			Source:          rcvr.RemoteAddr.String(),
			response:        make(chan hkp.Response),
			verifiedDomains: verifiedDomains}

		//PRC Start

		go func() {
			r.RecoverKey <- recoverKey
		}()
		resp := <-recoverKey.response
		if resp != nil && resp.Error() != nil {
			log.Println("Error Adding key :", resp.Error())
		}
		//PRC End
	}
	// Read last two bytes (CRLF, why?), or SKS will complain.
	body.Read(make([]byte, 2))
	return
}

func (r *SksPeer) Stop() {
	r.Peer.Stop()
}

func (r *SksPeer) deleteLocal(rcvr *recon.Recover, elements *ZSet) (err error) {

	defer fmt.Println("Error While Returning from deleteLocal", err)

	items := elements.Items()
	for len(items) > 0 {
		// Chunk requests to keep the hashquery message size and peer load reasonable.
		chunksize := RequestChunkSize
		if chunksize > len(items) {
			chunksize = len(items)
		}
		chunk := items[:chunksize]
		items = items[chunksize:]
		err = r.deleteLocalChunk(rcvr, chunk)
		if err != nil {
			log.Println(err)
		}
	}
	return
}

func (r *SksPeer) deleteLocalChunk(rcvr *recon.Recover, chunk []*Zp) (err error) {
	//Get MappedDomains for authenticatioon of add
	verifiedDomains, errM := RecoveryAuthentication(rcvr.RemoteAllStatesJSON)
	if errM != nil {
		err = errM
		return
	}

	//fmt.Println("deleteLocal", verifiedDomains)

	// Search keys from Local DB
	hqBuf := bytes.NewBuffer(nil)
	err = recon.WriteInt(hqBuf, len(chunk))
	if err != nil {
		return err
	}
	for _, z := range chunk {
		zb := z.Bytes()
		zb = recon.PadSksElement(zb)
		// Hashquery elements are 16 bytes (length_of(P_SKS)-1)
		zb = zb[:len(zb)-1]
		err = recon.WriteInt(hqBuf, len(zb))
		if err != nil {
			return err
		}
		_, err = hqBuf.Write(zb)
		if err != nil {
			return err
		}
	}
	ownAuth, err1 := GetOwnAuthority()
	if err1 != nil {
		err = err1
		return
	}
	fmt.Println("Making HashQuerry to self for = ", string(hqBuf.Bytes()))
	resp, err := http.Post(fmt.Sprintf("http://%s/pks/hashquery", ownAuth.HkpAddr),
		"sks/hashquery", bytes.NewReader(hqBuf.Bytes()))
	if err != nil {
		return err
	}

	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	{
		defer resp.Body.Close()
		bodyBuf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(bodyBuf)
	}
	var nkeys, keyLen int
	nkeys, err = recon.ReadInt(body)
	if err != nil {
		return err
	}
	log.Println("Response from Self:", nkeys, " keys found")
	fmt.Println("Response from Self:", nkeys, " keys found")

	for i := 0; i < nkeys; i++ {
		keyLen, err = recon.ReadInt(body)
		if err != nil {
			return err
		}
		keyBuf := bytes.NewBuffer(nil)
		_, err = io.CopyN(keyBuf, body, int64(keyLen))
		if err != nil {
			return err
		}
		log.Println("Key#", i+1, ":", keyLen, "bytes")
		// Merge locally

		localDeleteKey := &LocalDeleteKey{
			Keytext:         keyBuf.Bytes(),
			response:        make(chan hkp.Response),
			verifiedDomains: verifiedDomains}

		//PRC End
		go func() {
			r.LocalDeleteKey <- localDeleteKey

		}()

		resp := <-localDeleteKey.response
		if resp != nil && resp.Error() != nil {
			log.Println("Error Deleting key:", resp.Error())
		}

	}

	// Read last two bytes (CRLF, why?), or SKS will complain.
	body.Read(make([]byte, 2))
	return
}

func ReconGetRemoteStates(remoteAddr string) (remoteStatesInJSON string, err error) {
	fmt.Println("Reconing with ", remoteAddr)

	//TODO: Find a way to make it non blocking,may be send remotestates to channel
	fmt.Println("recon.go:Requesting States From Peer ", remoteAddr)

	remoteStates, err2 := GetAllStatesFromPeer(remoteAddr)
	if err2 != nil {
		fmt.Println(err2)
		fmt.Println("Error While Getting state from peer ", remoteAddr)
		err = err2
		return
	}
	fmt.Println("recon.go:Got States From Peer")
	remoteStatesJSON, err3 := WriteStatesToJSON(remoteStates)
	if err3 != nil {
		fmt.Println(err3)
		fmt.Println("Error While Encoding States from peer ", remoteAddr)
		err = err3
		return
	}
	remoteStatesInJSON = remoteStatesJSON
	ownSt, err1 := GetOwnCurrentState(remoteAddr)
	if err1 != nil {
		fmt.Println("Error while Getting OwnState for ", remoteAddr)
		fmt.Println(err1)
		err = err1
		return
	}
	err1 = SaveToLocalStates(ownSt, remoteStatesInJSON)
	if err1 != nil {
		fmt.Println(err1)
		fmt.Println("Error while Saving OwnState for ", remoteAddr)
		err = err1
		return
	}
	return

}

//PRC End
