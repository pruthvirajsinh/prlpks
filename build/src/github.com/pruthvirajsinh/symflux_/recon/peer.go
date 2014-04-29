/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package recon

import (
	"bufio"
	"errors"
	"fmt"
	. "github.com/pruthvirajsinh/symflux"
	"log"
	"net"
	"time"
)

const SERVE = "serve:"

type Recover struct {
	RemoteAddr     net.Addr
	RemoteConfig   *Config
	RemoteElements []*Zp //Elements that peer has but we dont,get these elements
	//PRC Start
	LocalElements       []*Zp //Elements that we have but the peer doesnt,clean these elements
	RemoteAllStatesJSON string
	//PRC End
}

//PRC End
func (r *Recover) String() string {
	return fmt.Sprintf("%v: %d elements", r.RemoteAddr, len(r.RemoteElements))
}

func (r *Recover) HkpAddr() (string, error) {
	// Use remote HKP host:port as peer-unique identifier
	host, _, err := net.SplitHostPort(r.RemoteAddr.String())
	if err != nil {
		log.Println("Cannot parse HKP remote address from", r.RemoteAddr, ":", err)
		return "", err
	}
	return fmt.Sprintf("%s:%d", host, r.RemoteConfig.HttpPort), nil
}

type RecoverChan chan *Recover

var PNodeNotFound error = errors.New("Prefix-tree node not found")

var RemoteRejectConfigError error = errors.New("Remote rejected configuration")

type reconCmd func() error

type reconCmdReq chan reconCmd
type reconCmdResp chan error

type Peer struct {
	*Settings
	PrefixTree
	RecoverChan  RecoverChan
	reconCmdReq  reconCmdReq
	reconCmdResp reconCmdResp
	serverStop   chan stopNotify
	gossipStop   chan stopNotify
	paused       bool
}

func NewPeer(settings *Settings, tree PrefixTree) *Peer {
	return &Peer{
		RecoverChan:  make(RecoverChan),
		Settings:     settings,
		PrefixTree:   tree,
		reconCmdReq:  make(reconCmdReq),
		reconCmdResp: make(reconCmdResp)}
}

func NewMemPeer() *Peer {
	settings := DefaultSettings()
	tree := new(MemPrefixTree)
	tree.Init()
	return NewPeer(settings, tree)
}

func (p *Peer) Start() {
	if p.serverStop != nil {
		return
	}
	p.gossipStop = make(chan stopNotify)
	p.serverStop = make(chan stopNotify)
	go p.Serve()
	go p.Gossip()
	go p.HandleCmds()
}

type stopNotify chan interface{}

func (p *Peer) Stop() {
	if p.serverStop == nil {
		return
	}
	log.Println("Stopping server & client...")
	serverStopped := make(stopNotify)
	gossipStopped := make(stopNotify)
	go func() { p.serverStop <- serverStopped }()
	go func() { p.gossipStop <- gossipStopped }()
	<-serverStopped
	<-gossipStopped
	log.Println("Done")
	p.serverStop = nil
	p.gossipStop = nil
}

func (p *Peer) Pause() {
	p.paused = true
}

func (p *Peer) Resume() {
	p.paused = false
}

// HandleCmds executes recon cmds in a single goroutine.
// This forces sequential reads and writes to the prefix
// tree.
func (p *Peer) HandleCmds() {
	for {
		select {
		case cmd, ok := <-p.reconCmdReq:
			if !ok {
				return
			}
			p.reconCmdResp <- cmd()
		}
	}
}

func (p *Peer) ExecCmd(cmd reconCmd) (err error) {
	p.reconCmdReq <- cmd
	err = <-p.reconCmdResp
	if err != nil {
		log.Println("CMD", err)
	}
	return
}

func (p *Peer) Insert(z *Zp) (err error) {
	return p.ExecCmd(func() error {
		return p.PrefixTree.Insert(z)
	})
}

func (p *Peer) Remove(z *Zp) (err error) {
	return p.ExecCmd(func() error {
		return p.PrefixTree.Remove(z)
	})
}

func (p *Peer) Serve() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.ReconPort()))
	if err != nil {
		log.Print(err)
		return
	}
	defer ln.Close()
	for {
		select {
		case stop, _ := <-p.serverStop:
			if stop != nil {
				stop <- new(interface{})
				return
			}
			return
		default:
		}
		if p.ConnTimeout() > 0 {
			ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second * time.Duration(p.ConnTimeout())))
		}
		conn, err := ln.Accept()
		if err != nil {
			log.Println(SERVE, err)
			continue
		}
		if p.ReadTimeout() > 0 {
			conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(p.ReadTimeout())))
		}
		go func() {
			err = p.Accept(conn)
			if err != nil {
				log.Println(SERVE, err)
			}
		}()
	}
}

func (p *Peer) handleConfig(conn net.Conn, role string) (remoteConfig *Config, err error) {
	// Send config to server on connect
	go func() {
		log.Println(role, "writing config:", p.Config())
		err = WriteMsg(conn, p.Config())
		if err != nil {
			return
		}
	}()
	// Receive remote peer's config
	log.Println(role, "reading remote config:", conn.RemoteAddr())
	var msg ReconMsg
	msg, err = ReadMsg(conn)
	if err != nil {
		return
	}
	var is bool
	remoteConfig, is = msg.(*Config)
	if !is {
		err = errors.New(fmt.Sprintf(
			"Remote config: expected config message, got %v", msg))
		return
	}
	log.Println(role, "remote config:", remoteConfig)
	if remoteConfig.BitQuantum != p.Config().BitQuantum {
		bufw := bufio.NewWriter(conn)
		WriteString(bufw, RemoteConfigFailed)
		WriteString(bufw, "mismatched bitquantum")
		bufw.Flush()
		log.Println(role, "Cannot peer: BitQuantum remote=", remoteConfig.BitQuantum,
			"!=", p.Config().BitQuantum)
		err = IncompatiblePeerError
		return
	}
	if remoteConfig.MBar != p.Config().MBar {
		bufw := bufio.NewWriter(conn)
		WriteString(bufw, RemoteConfigFailed)
		WriteString(bufw, "mismatched mbar")
		bufw.Flush()
		log.Println(role, "Cannot peer: MBar remote=", remoteConfig.MBar,
			"!=", p.Config().MBar)
		err = IncompatiblePeerError
		return
	}
	go func() {
		bufw := bufio.NewWriter(conn)
		err = WriteString(bufw, RemoteConfigPassed)
		if err != nil {
			return
		}
		err = bufw.Flush()
		if err != nil {
			return
		}
	}()
	remoteConfigStatus, err := ReadString(conn)
	if remoteConfigStatus != RemoteConfigPassed {
		var reason string
		if reason, err = ReadString(conn); err == nil {
			log.Println(role, reason)
			err = RemoteRejectConfigError
		}
		return
	}
	return
}

func (p *Peer) Accept(conn net.Conn) error {
	log.Println(SERVE, "connection from:", conn.RemoteAddr())
	remoteConfig, err := p.handleConfig(conn, SERVE)
	if err != nil {
		return err
	}
	return p.ExecCmd(func() (err error) {
		if !p.paused {
			err = p.interactWithClient(conn, remoteConfig, NewBitstring(0))
		}
		defer conn.Close()
		return err
	})
}

type requestEntry struct {
	node PrefixNode
	key  *Bitstring
}

func (r *requestEntry) String() string {
	if r == nil {
		return "nil"
	}
	return fmt.Sprintf("Request entry key=%v", r.key)
}

type bottomEntry struct {
	*requestEntry
	state reconState
}

func (r *bottomEntry) String() string {
	if r == nil {
		return "nil"
	} else if r.requestEntry == nil {
		return fmt.Sprintf("Bottom entry req=nil state=%v", r.state)
	}
	return fmt.Sprintf("Bottom entry key=%v state=%v", r.key, r.state)
}

type reconState uint8

const (
	reconStateBottom     = reconState(iota)
	reconStateFlushEnded = reconState(iota)
)

func (rs reconState) String() string {
	switch rs {
	case reconStateFlushEnded:
		return "Flush Ended"
	case reconStateBottom:
		return "Bottom"
	}
	return "Unknown"
}

type reconWithClient struct {
	*Peer
	requestQ []*requestEntry
	bottomQ  []*bottomEntry
	rcvrSet  *ZSet
	//PRC Start
	lclSet *ZSet
	//PRC End
	flushing bool
	conn     net.Conn
	messages []ReconMsg
}

func (rwc *reconWithClient) pushBottom(bottom *bottomEntry) {
	rwc.bottomQ = append(rwc.bottomQ, bottom)
}

func (rwc *reconWithClient) pushRequest(req *requestEntry) {
	rwc.requestQ = append(rwc.requestQ, req)
}

func (rwc *reconWithClient) topBottom() *bottomEntry {
	if len(rwc.bottomQ) == 0 {
		return nil
	}
	return rwc.bottomQ[0]
}

func (rwc *reconWithClient) popBottom() *bottomEntry {
	if len(rwc.bottomQ) == 0 {
		return nil
	}
	result := rwc.bottomQ[0]
	rwc.bottomQ = rwc.bottomQ[1:]
	return result
}

func (rwc *reconWithClient) popRequest() *requestEntry {
	if len(rwc.requestQ) == 0 {
		return nil
	}
	result := rwc.requestQ[0]
	rwc.requestQ = rwc.requestQ[1:]
	return result
}

func (rwc *reconWithClient) isDone() bool {
	return len(rwc.requestQ) == 0 && len(rwc.bottomQ) == 0
}

func (rwc *reconWithClient) sendRequest(p *Peer, req *requestEntry) {
	var msg ReconMsg
	if req.node.IsLeaf() || (req.node.Size() < p.MBar()) {
		msg = &ReconRqstFull{
			Prefix:   req.key,
			Elements: NewZSet(req.node.Elements()...)}
	} else {
		msg = &ReconRqstPoly{
			Prefix:  req.key,
			Size:    req.node.Size(),
			Samples: req.node.SValues()}
	}
	log.Println(SERVE, "sendRequest:", msg)
	rwc.messages = append(rwc.messages, msg)
	rwc.pushBottom(&bottomEntry{requestEntry: req})
}

func (rwc *reconWithClient) handleReply(p *Peer, msg ReconMsg, req *requestEntry, conn net.Conn) (err error) {
	log.Println(SERVE, "handleReply:", "got:", msg)
	switch m := msg.(type) {
	case *SyncFail:
		if req.node.IsLeaf() {
			return errors.New("Syncfail received at leaf node")
		}
		log.Println(SERVE, "SyncFail: pushing children")
		for _, childNode := range req.node.Children() {
			log.Println(SERVE, "push:", childNode.Key())
			rwc.pushRequest(&requestEntry{key: childNode.Key(), node: childNode})
		}
	case *Elements:
		fmt.Println("Rcvd RemoteSet", len(m.ZSet.Items()))
		//rwc.rcvrSet.AddAll(m.ZSet)
	//Earlier client was sending only elements that server needs to recover,now it also sends elements that it may delete in LcElements
	//Hence Read Next message also which is a LcElement
	case *LcElements:
		rwc.rcvrSet.AddAll(m.remoteElements)
		rwc.lclSet.AddAll(m.localElements)
		//fmt.Println("Server:Rcvd LcElements RE:", len(m.remoteElements.Items()), " LE:", len(m.localElements.Items()))
	case *FullElements:
		local := NewZSet(req.node.Elements()...)
		localdiff := ZSetDiff(local, m.ZSet)
		remotediff := ZSetDiff(m.ZSet, local)
		lcElementsMsg := &LcElements{remoteElements: localdiff, localElements: remotediff}
		log.Println(SERVE, "handleReply:", "sending:", lcElementsMsg)
		rwc.messages = append(rwc.messages, lcElementsMsg)
		rwc.rcvrSet.AddAll(remotediff)
		//PRC Start
		rwc.lclSet.AddAll(localdiff)
		//PRC End
	default:
		err = errors.New(fmt.Sprintf("unexpected message: %v", m))
	}
	return
}

func (rwc *reconWithClient) flushQueue() {
	log.Println(SERVE, "flush queue")
	rwc.messages = append(rwc.messages, &Flush{})
	err := WriteMsg(rwc.conn, rwc.messages...)
	if err != nil {
		log.Println(SERVE, "Error writing messages:", err)
	}
	rwc.messages = nil
	rwc.pushBottom(&bottomEntry{state: reconStateFlushEnded})
	rwc.flushing = true
}

func (p *Peer) interactWithClient(conn net.Conn, remoteConfig *Config, bitstring *Bitstring) (err error) {
	log.Println(SERVE, "interacting with client")
	recon := reconWithClient{Peer: p, conn: conn, rcvrSet: NewZSet(), lclSet: NewZSet()}
	var root PrefixNode
	root, err = p.Root()
	if err != nil {
		return
	}
	recon.pushRequest(&requestEntry{node: root, key: bitstring})
	for !recon.isDone() {
		bottom := recon.topBottom()
		log.Println(SERVE, "interact: bottom:", bottom)
		switch {
		case bottom == nil:
			req := recon.popRequest()
			log.Println(SERVE, "interact: popRequest:", req, "sending...")
			recon.sendRequest(p, req)
		case bottom.state == reconStateFlushEnded:
			log.Println(SERVE, "interact: flush ended, popBottom")
			recon.popBottom()
			recon.flushing = false
		case bottom.state == reconStateBottom:
			log.Println(SERVE, "Queue length:", len(recon.bottomQ))
			var msg ReconMsg
			var hasMsg bool
			// Set a small read timeout to simulate non-blocking I/O
			if err = conn.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
				log.Println(SERVE, "Warning:", err)
			}
			msg, err = ReadMsg(conn)
			hasMsg = (err == nil)
			// Restore blocking I/O
			if err = conn.SetReadDeadline(time.Unix(int64(0), int64(0))); err != nil {
				log.Println(SERVE, "Warning:", err)
			}
			if hasMsg {
				recon.popBottom()
				err = recon.handleReply(p, msg, bottom.requestEntry, conn)
			} else if len(recon.bottomQ) > p.MaxOutstandingReconRequests() ||
				len(recon.requestQ) == 0 {
				if !recon.flushing {
					recon.flushQueue()
				} else {
					recon.popBottom()
					if msg, err = ReadMsg(conn); err != nil {
						log.Println("peer: error while reading msg ", err)
						return
					}
					log.Println("Reply:", msg)
					err = recon.handleReply(p, msg, bottom.requestEntry, conn)
				}
			} else {
				req := recon.popRequest()
				recon.sendRequest(p, req)
			}
		default:
			log.Println("failed to match expected patterns")
		}
		if err != nil {
			return
		}
	}
	WriteMsg(conn, &Done{})
	items := recon.rcvrSet.Items()
	localItems := recon.lclSet.Items()
	if len(items) > 0 || len(localItems) > 0 {
		fmt.Println("peer.go:Sending Recover Out with remote Items = ", len(items), " Local Items = ", len(localItems))
		p.RecoverChan <- &Recover{
			RemoteAddr:     conn.RemoteAddr(),
			RemoteConfig:   remoteConfig,
			RemoteElements: items,
			//PRC Start
			LocalElements:       localItems,
			RemoteAllStatesJSON: ""}
		//PRC End
	} else {
		fmt.Println("As a Server:Reconciled at ", time.Now().String())
	}
	return
}
