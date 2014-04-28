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
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	. "github.com/pruthvirajsinh/prlpks/errors"
	"github.com/pruthvirajsinh/prlpks/hkp"
	"github.com/pruthvirajsinh/prlpks/util"
)

const LOOKUP_RESULT_LIMIT = 100

type Worker struct {
	*Loader
	Service    *hkp.Service
	Peer       *SksPeer
	keyChanges KeyChangeChan
}

// Number of workers to spawn
func (s *Settings) NumWorkers() int {
	return s.GetIntDefault("prlpks.openpgp.nworkers", runtime.NumCPU())
}

func (s *Settings) Driver() string {
	return s.GetStringDefault("prlpks.openpgp.db.driver", "postgres")
}

func currentUsername() (username string) {
	if me, err := user.Current(); err != nil {
		username = os.Getenv("USER")
	} else {
		username = me.Name
	}
	return
}

func (s *Settings) DSN() string {
	return s.GetStringDefault("prlpks.openpgp.db.dsn",
		fmt.Sprintf("dbname=hkp host=/var/run/postgresql sslmode=disable user=%s",
			currentUsername()))
}

func NewWorker(service *hkp.Service, peer *SksPeer) (w *Worker, err error) {
	w = &Worker{Loader: &Loader{}, Service: service, Peer: peer}
	if w.db, err = NewDB(); err != nil {
		return
	}
	err = w.db.CreateSchema()
	return
}

func (w *Worker) Run() {
	for {
		select {
		case req, ok := <-w.Service.Requests:
			if !ok {
				return
			}
			switch r := req.(type) {
			case *hkp.Lookup:
				w.Lookup(r)
			case *hkp.Add:
				w.Add(r)
			case *hkp.HashQuery:
				w.HashQuery(r)
			//PRC ADD
			case *hkp.OTLVerify:
				w.PRCOTLVerify(r)
			case *hkp.DeleteReq:
				w.HandleDeleteReq(r)
			case *hkp.AllStatesReq:
				w.HandleAllStatesReq(r)
			//PRC END

			default:
				log.Println("Unsupported HKP service request:", req)
			}
		case r, ok := <-w.Peer.RecoverKey:
			if !ok {
				return
			}
			resp := w.recoverKey(r)
			log.Println(resp)
			r.response <- resp
		case r1, ok := <-w.Peer.LocalDeleteKey:
			if !ok {
				return
			}
			resp := w.reconDeleteKey(r1)
			log.Println(resp)
			r1.response <- resp
		}
	}
}

func (w *Worker) Lookup(l *hkp.Lookup) {
	// Dispatch the lookup operation to the correct query
	if l.Op == hkp.Stats {
		w.Stats(l)
		return
	} else if l.Op == hkp.UnknownOperation {
		l.Response() <- &ErrorResponse{hkp.ErrorUnknownOperation("")}
		return
	}
	//PRC Start
	delegated := false
	//PRC End

	var keys []*Pubkey
	var limit int = LOOKUP_RESULT_LIMIT
	var err error
	if l.Op == hkp.HashGet {
		keys, err = w.LookupHash(l.Search)
	} else {
		keys, err = w.LookupKeys(l.Search, limit)
		if err == ErrKeyNotFound || len(keys) <= 0 {
			tmpKey, err1 := w.LookupKey(l.Search)
			if err1 == nil {
				keys = append(keys, tmpKey)
			} else {
				//PRC Start
				//Delegate to SKS
				//if len(keys) < 1
				//Do a Query with 0x
				if Config().GetBool("authority.delegateToPKS") {
					sksServer := Config().GetStringDefault("authority.delegateAddress", "pool.sks-keyservers.net:11371")
					keys, err = DelegateToSKS(l.Search, sksServer)
					if len(keys) < 1 || err != nil {
						keys, err = DelegateToSKS("0x"+l.Search, sksServer)
					}
					if len(keys) > 0 && err == nil {
						delegated = true
					}
				}
			}
			//PRC End
		}

	}
	if err != nil {
		l.Response() <- &ErrorResponse{err}
		return
	}
	// Formulate a response
	var resp hkp.Response
	switch l.Op {
	case hkp.Get:
		resp = &KeyringResponse{keys}
	case hkp.HashGet:
		resp = &KeyringResponse{keys}
	case hkp.Index:
		//PRC Original in HP
		//resp = &IndexResponse{Lookup: l, Keys: keys}
		resp = &IndexResponse{Lookup: l, Keys: keys, Delegated: delegated}
	case hkp.Vindex:
		//PRC Original in HP
		//resp = &IndexResponse{Lookup: l, Keys: keys, Verbose: true}
		resp = &IndexResponse{Lookup: l, Keys: keys, Verbose: true, Delegated: delegated}
	default:
		resp = &ErrorResponse{ErrUnsupportedOperation}
		return
	}
	l.Response() <- resp
}

func (w *Worker) HashQuery(hq *hkp.HashQuery) {
	var uuids []string
	for _, digest := range hq.Digests {
		uuid, err := w.lookupMd5Uuid(digest)
		if err != nil {
			log.Println("Hashquery lookup failed:", err)
			hq.Response() <- &ErrorResponse{err}
			return
		}
		uuids = append(uuids, uuid)
	}
	keys := w.fetchKeys(uuids)
	hq.Response() <- &HashQueryResponse{keys.GoodKeys()}
}

func (w *Worker) LookupKeys(search string, limit int) (keys []*Pubkey, err error) {
	uuids, err := w.lookupPubkeyUuids(search, limit)
	return w.fetchKeys(uuids).GoodKeys(), err
}

func (w *Worker) LookupHash(digest string) ([]*Pubkey, error) {
	uuid, err := w.lookupMd5Uuid(digest)
	return w.fetchKeys([]string{uuid}).GoodKeys(), err
}

func (w *Worker) WriteKeys(wr io.Writer, uuids []string) error {
	// Stream OpenPGP binary packets directly out of the database.
	stmt, err := w.db.Preparex(`
SELECT bytea FROM openpgp_pubkey pk WHERE uuid = $1 UNION
SELECT bytea FROM openpgp_sig s
	JOIN openpgp_pubkey_sig pks ON (s.uuid = pks.sig_uuid)
	WHERE pks.pubkey_uuid = $1 ORDER BY creation UNION
SELECT bytea FROM (
	SELECT bytea, 1 AS level, uuid AS subkey_uuid
		FROM openpgp_subkey sk WHERE pubkey_uuid = $1 UNION
	SELECT bytea, 2 AS level, subkey_uuid FROM openpgp_sig s
		JOIN openpgp_subkey_sig sks ON (s.uuid = sks.sig_uuid)
		WHERE sks.pubkey_uuid = $1) ORDER BY subkey_uuid, level UNION
SELECT bytea FROM (
	SELECT bytea, 1 AS level, uuid AS uid_uuid, creation
		FROM openpgp_uid u WHERE pubkey_uuid = $1 UNION
	SELECT bytea, 2 AS level, uid_uuid, creation FROM openpgp_sig s
		JOIN openpgp_uid_sig us ON (s.uuid = us.sig_uuid)
		WHERE us.pubkey_uuid = $1) ORDER BY creation, uid_uuid, level UNION
SELECT bytea FROM (
	SELECT bytea, 1 AS level, uuid AS uat, creation
		FROM openpgp_uat u WHERE pubkey_uuid = $1 UNION
	SELECT bytea, 2 AS level, uat, creation FROM openpgp_sig s
		JOIN openpgp_uat_sig uas ON (s.uuid = uas.sig_uuid)
		WHERE uas.pubkey_uuid = $1) ORDER BY creation, uat_uuid, level`)
	if err != nil {
		return err
	}
	for _, uuid := range uuids {
		rows, err := stmt.Query(uuid)
		if err != nil {
			return err
		}
		for rows.Next() {
			var packet []byte
			err = rows.Scan(&packet)
			if err != nil {
				return err
			}
			_, err = wr.Write(packet)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *Worker) lookupPubkeyUuids(search string, limit int) (uuids []string, err error) {
	if strings.HasPrefix(search, "0x") {
		return w.lookupKeyidUuids(search[2:])
	}
	return w.lookupKeywordUuids(search, limit)
}

func (w *Worker) lookupMd5Uuid(hash string) (uuid string, err error) {
	rows, err := w.db.Queryx(`SELECT uuid FROM openpgp_pubkey WHERE md5 = $1`,
		strings.ToLower(hash))
	if err == sql.ErrNoRows {
		return "", ErrKeyNotFound
	} else if err != nil {
		return
	}
	var uuids []string
	uuids, err = flattenUuidRows(rows)
	if err != nil {
		return
	}
	if len(uuids) < 1 {
		return "", ErrKeyNotFound
	}
	uuid = uuids[0]
	if len(uuids) > 1 {
		return uuid, ErrKeyIdCollision
	}
	return
}

func (w *Worker) lookupKeyidUuids(keyId string) (uuids []string, err error) {
	keyId = strings.ToLower(keyId)
	raw, err := hex.DecodeString(keyId)
	if err != nil {
		return nil, ErrInvalidKeyId
	}
	rKeyId := util.Reverse(keyId)
	var compareOp string
	switch len(raw) {
	case 4:
		compareOp = "LIKE $1 || '________________________________'"
	case 8:
		compareOp = "LIKE $1 || '________________________'"
	case 16:
		return []string{rKeyId}, nil
	case 20:
		return []string{rKeyId}, nil
	default:
		return nil, ErrInvalidKeyId
	}
	rows, err := w.db.Queryx(fmt.Sprintf(`
SELECT uuid FROM openpgp_pubkey WHERE uuid %s
UNION
SELECT pubkey_uuid FROM openpgp_subkey WHERE uuid %s`, compareOp, compareOp), rKeyId)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return
	}
	return flattenUuidRows(rows)
}

func flattenUuidRows(rows *sqlx.Rows) (uuids []string, err error) {
	for rows.Next() {
		var uuid string
		err = rows.Scan(&uuid)
		if err != nil {
			return
		}
		uuids = append(uuids, uuid)
	}
	return
}

func (w *Worker) lookupKeywordUuids(search string, limit int) (uuids []string, err error) {
	search = strings.Join(strings.Split(search, " "), "+")
	log.Println("keyword:", search)
	log.Println("limit:", limit)
	rows, err := w.db.Queryx(`
SELECT DISTINCT pubkey_uuid FROM openpgp_uid
WHERE keywords_fulltext @@ to_tsquery($1) LIMIT $2`, search, limit)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return
	}
	return flattenUuidRows(rows)
}

var ErrInternalKeyInvalid error = errors.New("Internal integrity error matching key")

func (w *Worker) LookupKey(keyid string) (pubkey *Pubkey, err error) {
	uuids, err := w.lookupKeyidUuids(keyid)
	if err != nil {
		return nil, err
	}
	if len(uuids) < 1 {
		return nil, ErrKeyNotFound
	}
	if len(uuids) > 1 {
		return nil, ErrKeyIdCollision
	}
	return w.fetchKey(uuids[0])
}

func (w *Worker) fetchKeys(uuids []string) (results ReadKeyResults) {
	for _, uuid := range uuids {
		key, err := w.fetchKey(uuid)
		results = append(results, &ReadKeyResult{Pubkey: key, Error: err})
		if err != nil {
			log.Println("Fetch key:", err)
		}
	}
	return
}

func (w *Worker) fetchKey(uuid string) (pubkey *Pubkey, err error) {
	pubkey = new(Pubkey)
	err = w.db.Get(pubkey, `SELECT * FROM openpgp_pubkey WHERE uuid = $1`, uuid)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return
	}
	if err = pubkey.Read(); err != nil {
		return
	}
	// Retrieve all signatures made directly on the primary public key
	sigs := []Signature{}
	err = w.db.Select(&sigs, `
SELECT sig.* FROM openpgp_sig sig
	JOIN openpgp_pubkey_sig pksig ON (sig.uuid = pksig.sig_uuid)
WHERE pksig.pubkey_uuid = $1`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.signatures = toSigPtrSlice(sigs)
	for _, sig := range pubkey.signatures {
		if err = sig.Read(); err != nil {
			return
		}
	}
	// Retrieve all uid records
	uids := []UserId{}
	err = w.db.Select(&uids, `
SELECT uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid, keywords
FROM openpgp_uid WHERE pubkey_uuid = $1`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.userIds = toUidPtrSlice(uids)
	for _, uid := range pubkey.userIds {
		if err = uid.Read(); err != nil {
			return
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
SELECT sig.* FROM openpgp_sig sig
	JOIN openpgp_uid_sig usig ON (sig.uuid = usig.sig_uuid)
WHERE usig.uid_uuid = $1`, uid.ScopedDigest)
		if err != nil && err != sql.ErrNoRows {
			return
		}
		uid.signatures = toSigPtrSlice(sigs)
		for _, sig := range uid.signatures {
			if err = sig.Read(); err != nil {
				return
			}
		}
	}
	// Retrieve all user attribute records
	uats := []UserAttribute{}
	err = w.db.Select(&uats,
		`SELECT * FROM openpgp_uat WHERE pubkey_uuid = $1`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.userAttributes = toUatPtrSlice(uats)
	for _, uat := range pubkey.userAttributes {
		if err = uat.Read(); err != nil {
			return
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
SELECT sig.* FROM openpgp_sig sig
	JOIN openpgp_uat_sig usig ON (sig.uuid = usig.sig_uuid)
WHERE usig.uat_uuid = $1`, uat.ScopedDigest)
		if err != nil && err != sql.ErrNoRows {
			return
		}
		uat.signatures = toSigPtrSlice(sigs)
		for _, sig := range uat.signatures {
			if err = sig.Read(); err != nil {
				return
			}
		}
	}
	// Retrieve all subkey records
	subkeys := []Subkey{}
	err = w.db.Select(&subkeys,
		`SELECT * FROM openpgp_subkey WHERE pubkey_uuid = $1`, uuid)
	if err != nil && err != sql.ErrNoRows {
		return
	}
	pubkey.subkeys = toSubkeyPtrSlice(subkeys)
	for _, subkey := range pubkey.subkeys {
		if err = subkey.Read(); err != nil {
			return
		}
		sigs = []Signature{}
		err = w.db.Select(&sigs, `
SELECT sig.* FROM openpgp_sig sig
	JOIN openpgp_subkey_sig sksig ON (sig.uuid = sksig.sig_uuid)
WHERE sksig.subkey_uuid = $1`, subkey.RFingerprint)
		if err != nil && err != sql.ErrNoRows {
			return
		}
		subkey.signatures = toSigPtrSlice(sigs)
		for _, sig := range subkey.signatures {
			if err = sig.Read(); err != nil {
				return
			}
		}
	}
	Resolve(pubkey)
	return
}

func toSigPtrSlice(recs []Signature) (result []*Signature) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}

func toUidPtrSlice(recs []UserId) (result []*UserId) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}

func toUatPtrSlice(recs []UserAttribute) (result []*UserAttribute) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}

func toSubkeyPtrSlice(recs []Subkey) (result []*Subkey) {
	for i := 0; i < len(recs); i++ {
		result = append(result, &(recs[i]))
	}
	return
}
