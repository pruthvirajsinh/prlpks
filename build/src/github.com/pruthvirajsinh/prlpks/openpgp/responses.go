/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package openpgp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/pruthvirajsinh/symflux/recon"

	"github.com/pruthvirajsinh/prlpks"
	. "github.com/pruthvirajsinh/prlpks/errors"
	"github.com/pruthvirajsinh/prlpks/hkp"
)

type ErrorResponse struct {
	Err error
}

func (r *ErrorResponse) Error() error {
	return r.Err
}

func (r *ErrorResponse) WriteTo(w http.ResponseWriter) error {
	w.WriteHeader(400)
	fmt.Fprintf(w, prlpks.BAD_REQUEST)
	log.Println(r.Err)
	return r.Err
}

type MessageResponse struct {
	Content []byte
	Err     error
}

func (r *MessageResponse) Error() error {
	return r.Err
}

func (r *MessageResponse) WriteTo(w http.ResponseWriter) error {
	w.Write([]byte(r.Content))
	return r.Err
}

type AddResponse struct {
	Changes []*KeyChange
	Errors  []*ReadKeyResult
}

func (r *AddResponse) Error() error {
	if len(r.Changes) > 0 || len(r.Errors) == 0 {
		return nil
	}
	return errors.New("One or more keys had an error")
}

func (r *AddResponse) WriteTo(w http.ResponseWriter) (err error) {
	if hkp.AddResultTemplate == nil {
		return ErrTemplatePathNotFound
	}
	err = hkp.AddResultTemplate.ExecuteTemplate(w, "top", r)
	if err != nil {
		return
	}
	err = hkp.AddResultTemplate.ExecuteTemplate(w, "page_content", r)
	if err != nil {
		return
	}
	err = hkp.AddResultTemplate.ExecuteTemplate(w, "bottom", r)
	return
}

type RecoverKeyResponse struct {
	Change *KeyChange
	Err    error
}

func (r *RecoverKeyResponse) Error() error {
	return r.Err
}

func (r *RecoverKeyResponse) WriteTo(w http.ResponseWriter) error {
	if r.Err != nil {
		return r.Err
	}
	fmt.Fprintf(w, "%v", r.Change)
	return nil
}

type StatsResponse struct {
	Lookup *hkp.Lookup
	Stats  *HkpStats
	Err    error
}

func (r *StatsResponse) Error() error {
	return r.Err
}

func (r *StatsResponse) WriteTo(w http.ResponseWriter) (err error) {
	err = r.Err
	if err != nil {
		return
	}
	if r.Lookup.Option&(hkp.JsonFormat|hkp.MachineReadable) != 0 {
		// JSON is the only supported machine readable stats format.
		w.Header().Add("Content-Type", "application/json")
		msg := map[string]interface{}{
			"timestamp": r.Stats.Timestamp,
			"hostname":  r.Stats.Hostname,
			"http_port": r.Stats.Port,
			"numkeys":   r.Stats.TotalKeys,
			"software":  filepath.Base(os.Args[0]),
			"version":   r.Stats.Version}
		// Convert hourly stats
		hours := []interface{}{}
		for _, hour := range r.Stats.KeyStatsHourly {
			hours = append(hours, map[string]interface{}{
				"time":         hour.Timestamp.Unix(),
				"new_keys":     hour.Created,
				"updated_keys": hour.Modified})
		}
		msg["stats_by_hour"] = hours
		// Convert daily stats
		days := []interface{}{}
		for _, day := range r.Stats.KeyStatsDaily {
			days = append(days, map[string]interface{}{
				"time":         day.Timestamp.Unix(),
				"new_keys":     day.Created,
				"updated_keys": day.Modified})
		}
		msg["stats_by_day"] = days
		// Convert mailsync stats
		mailPeers := []string{}
		for _, pksStat := range r.Stats.PksPeers {
			mailPeers = append(mailPeers, pksStat.Addr)
		}
		msg["mailsync_peers"] = mailPeers
		// Serialize and send
		var jsonStr []byte
		jsonStr, err = json.Marshal(msg)
		if err == nil {
			fmt.Fprintf(w, "%s", jsonStr)
		}
	} else {
		w.Header().Add("Content-Type", "text/html")
		if hkp.StatsTemplate == nil {
			return ErrTemplatePathNotFound
		}
		err = hkp.StatsTemplate.ExecuteTemplate(w, "layout", r.Stats)
	}
	return
}

type KeyringResponse struct {
	Keys []*Pubkey
}

func (k *KeyringResponse) Error() error {
	return nil
}

func (k *KeyringResponse) WriteTo(w http.ResponseWriter) error {
	for _, key := range k.Keys {
		err := WriteArmoredPackets(w, key)
		if err != nil {
			return err
		}
	}
	return nil
}

type HashQueryResponse struct {
	Keys []*Pubkey
}

func (hq *HashQueryResponse) Error() error {
	return nil
}

func (hq *HashQueryResponse) WriteTo(w http.ResponseWriter) (err error) {
	w.Header().Set("Content-Type", "pgp/keys")
	// Write the number of keys
	err = recon.WriteInt(w, len(hq.Keys))
	for _, key := range hq.Keys {
		// Write each key in binary packet format, prefixed with length
		keybuf := bytes.NewBuffer(nil)
		err = WritePackets(keybuf, key)
		if err != nil {
			return
		}
		err = recon.WriteInt(w, keybuf.Len())
		if err != nil {
			return
		}
		_, err = w.Write(keybuf.Bytes())
		if err != nil {
			return
		}
	}
	// SKS expects hashquery response to terminate with a CRLF
	_, err = w.Write([]byte{0x0d, 0x0a})
	return
}

type NotImplementedResponse struct {
}

func (e *NotImplementedResponse) Error() error {
	return errors.New("Not implemented")
}

func (e *NotImplementedResponse) WriteTo(w http.ResponseWriter) error {
	w.WriteHeader(400)
	return e.Error()
}

//PRC START
type DeleteResponse struct {
	DeleteResults []*DeleteResult
}

func (r *DeleteResponse) Error() error {
	if len(r.DeleteResults) > 0 {
		return nil
	}
	return errors.New("Could not delete key!")
}

func (r *DeleteResponse) WriteTo(w http.ResponseWriter) (err error) {
	if hkp.DeleteResultTemplate == nil {
		return ErrTemplatePathNotFound
	}
	err = hkp.DeleteResultTemplate.ExecuteTemplate(w, "top", r)
	if err != nil {
		return
	}
	err = hkp.DeleteResultTemplate.ExecuteTemplate(w, "page_content", r)
	if err != nil {
		return
	}
	err = hkp.DeleteResultTemplate.ExecuteTemplate(w, "bottom", r)
	return
}

//PRC END

//PRC START
type AllStatesResponse struct {
	AllStatesResults []*AllStatesResult
}

func (r *AllStatesResponse) Error() error {
	if len(r.AllStatesResults) > 0 {
		return nil
	}
	return errors.New("Could not process states request!")
}

func (r *AllStatesResponse) WriteTo(w http.ResponseWriter) (err error) {
	//Write JSON to ResponseWriter

	// JSON is the only supported machine readable stats format.
	w.Header().Add("Content-Type", "application/json")
	// Serialize and send
	var msg []AuthorizedState
	for _, allStateRes := range r.AllStatesResults {
		for _, authState := range allStateRes.allStates {
			msg = append(msg, authState)
		}
	}

	var jsonStr []byte
	jsonStr, err = json.Marshal(msg)
	if err == nil {
		fmt.Fprintf(w, "%s", string(jsonStr))
	} else {
		return
	}
	//TODO: Encrypt the state with pub Key of peer
	//fmt.Println("JSON in allState Response = %s", string(jsonStr))
	return
}

//PRC End

//PRC Start
type ReconDeleteResponse struct {
	Change *KeyChange
	Err    error
}

func (r *ReconDeleteResponse) Error() error {
	return r.Err
}

func (r *ReconDeleteResponse) WriteTo(w http.ResponseWriter) error {
	if r.Err != nil {
		return r.Err
	}
	fmt.Fprintf(w, "%v", r.Change)
	return nil
}

//PRC END
