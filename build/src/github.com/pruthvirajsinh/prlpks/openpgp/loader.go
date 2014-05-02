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
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/pruthvirajsinh/prlpks/util"
)

type Loader struct {
	db   *DB
	tx   *sqlx.Tx
	bulk bool
}

func NewLoader(db *DB, bulk bool) *Loader {
	return &Loader{db: db, bulk: bulk}
}

func (l *Loader) Begin() (_ *sqlx.Tx, err error) {
	l.tx, err = l.db.Beginx()
	return l.tx, err
}

func (l *Loader) Commit() (err error) {
	if err = l.tx.Commit(); err != nil {
		return
	}
	return
}

func (l *Loader) Rollback() (err error) {
	err = l.tx.Rollback()
	return
}

func (l *Loader) InsertKey(pubkey *Pubkey) (err error) {
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			if err := l.insertPubkey(r); err != nil {
				return err
			}
			signable = r
		case *Subkey:
			if err := l.insertSubkey(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserId:
			if err := l.insertUid(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			if err := l.insertUat(pubkey, r); err != nil {
				return err
			}
			signable = r
		case *Signature:
			if err := l.insertSig(pubkey, r); err != nil {
				return err
			}
			if err := l.insertSigRelations(pubkey, signable, r); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// insertSelectFrom completes an INSERT INTO .. SELECT FROM
// SQL statement based on the loader's bulk loading mode.
func (l *Loader) insertSelectFrom(sql, table, where string) string {
	if !l.bulk {
		sql = fmt.Sprintf("%s WHERE NOT EXISTS (SELECT 1 FROM %s WHERE %s)",
			sql, table, where)
	}
	return sql
}

func (l *Loader) insertPubkey(r *Pubkey) error {
	_, err := l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_pubkey (
	uuid, creation, expiration, state, packet,
	ctime, mtime,
    md5, sha256, revsig_uuid, primary_uid, primary_uat,
	algorithm, bit_len, unsupp)
SELECT $1, $2, $3, $4, $5,
	now(), now(),
    $6, $7, $8, $9, $10,
	$11, $12, $13`,
		"openpgp_pubkey", "uuid = $1"),
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
		// TODO: use mtime and ctime from record, or use RETURNING to set it
		r.Md5, r.Sha256, r.RevSigDigest, r.PrimaryUid, r.PrimaryUat,
		r.Algorithm, r.BitLen, r.Unsupported)
	return err
}

func (l *Loader) insertSubkey(pubkey *Pubkey, r *Subkey) error {
	_, err := l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_subkey (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid, algorithm, bit_len)
SELECT $1, $2, $3, $4, $5,
	$6, $7, $8, $9`,
		"openpgp_subkey", "uuid = $1"),
		r.RFingerprint, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest, r.Algorithm, r.BitLen)
	return err
}

func (l *Loader) insertUid(pubkey *Pubkey, r *UserId) error {
	_, err := l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_uid (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid, keywords, keywords_fulltext)
SELECT $1, $2, $3, $4, $5,
	$6, $7, $8, to_tsvector($8)`,
		"openpgp_uid", "uuid = $1"),
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest, util.CleanUtf8(r.Keywords))
	return err
}

func (l *Loader) insertUat(pubkey *Pubkey, r *UserAttribute) error {
	_, err := l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_uat (
	uuid, creation, expiration, state, packet,
	pubkey_uuid, revsig_uuid)
SELECT $1, $2, $3, $4, $5,
	$6, $7`,
		"openpgp_uat", "uuid = $1"),
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		pubkey.RFingerprint, r.RevSigDigest)
	return err
}

func (l *Loader) insertSig(pubkey *Pubkey, r *Signature) error {
	_, err := l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_sig (
	uuid, creation, expiration, state, packet,
	sig_type, signer, signer_uuid)
SELECT $1, $2, $3, $4, $5, $6, $7, $8`,
		"openpgp_sig", "uuid = $1"),
		r.ScopedDigest, r.Creation, r.Expiration, r.State, r.Packet,
		r.SigType, r.RIssuerKeyId, r.RIssuerFingerprint)
	// TODO: use RETURNING to update matched issuer fingerprint
	return err
}

func (l *Loader) insertSigRelations(pubkey *Pubkey, signable PacketRecord, r *Signature) error {
	sigRelationUuid, err := NewUuid()
	if err != nil {
		return err
	}
	// Add signature relation to other packets
	switch signed := signable.(type) {
	case *Pubkey:
		_, err = l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_pubkey_sig (uuid, pubkey_uuid, sig_uuid)
SELECT $1, $2, $3`,
			"openpgp_pubkey_sig", "pubkey_uuid = $2 AND sig_uuid = $3"),
			sigRelationUuid, signed.RFingerprint, r.ScopedDigest)
	case *Subkey:
		_, err = l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_subkey_sig (uuid, pubkey_uuid, subkey_uuid, sig_uuid)
SELECT $1, $2, $3, $4`,
			"openpgp_subkey_sig", "pubkey_uuid = $2 AND subkey_uuid = $3 AND sig_uuid = $4"),
			sigRelationUuid, pubkey.RFingerprint,
			signed.RFingerprint, r.ScopedDigest)
	case *UserId:
		_, err = l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_uid_sig (uuid, pubkey_uuid, uid_uuid, sig_uuid)
SELECT $1, $2, $3, $4`,
			"openpgp_uid_sig", "pubkey_uuid = $2 AND uid_uuid = $3 AND sig_uuid = $4"),
			sigRelationUuid, pubkey.RFingerprint,
			signed.ScopedDigest, r.ScopedDigest)
	case *UserAttribute:
		_, err = l.tx.Execv(l.insertSelectFrom(`
INSERT INTO openpgp_uat_sig (uuid, pubkey_uuid, uat_uuid, sig_uuid)
SELECT $1, $2, $3, $4`,
			"openpgp_uat_sig", "pubkey_uuid = $2 AND uat_uuid = $3 AND sig_uuid = $4"),
			sigRelationUuid, pubkey.RFingerprint,
			signed.ScopedDigest, r.ScopedDigest)
	}
	return err
}
