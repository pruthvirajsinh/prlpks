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
	"text/template"
)

/*

   Notes on prlpks OpenPGP SQL schema
   ======================================

   Common columns
   --------------
   Most tables contain the columns: uuid, creation, expiration and state.

   uuid
   ~~~~

   For public key records, the full 160-bit fingerprint is used, in a
   Base-16, "reversed" (LSB-to-MSB) form. The reversal is performance optimal for
   prefixed-substring "LIKE abc%" matching when searching for a shorter key ID.

   Other packets can lack inherent content uniqueness. While uncommon, it is not
   impossible for a User ID to have identical fields. Such a packet could even be
   specially crafted to attack the service's ability to correctly represent a key!

   In order to rule this out, and still keep the benefits of content-addressability,
   a special digest is calculated on each packet's content, scoped to the primary
   public key. This is calculated as:

	   base85 ( sha256 ( primary public key fingerprint || packet data ) )

   For other records that do not directly represent an OpenPGP packet, the UUID
   is a randomly generated value with an almost certain probability of uniqueness.
   A randomly-generated Base-85 ascii string, representative of 256 bits should suffice.

   creation & expiration
   ~~~~~~~~~~~~~~~~~~~~~
   Most tables represent an OpenPGP packet. These timestamps should copy the
   actual packet's content meaning as defined in RFC 4880, for query purposes.

   state
   ~~~~~
   The 'state' is a prlpks-reserved value which is intended to disposition
   records outside of the RFC 4880 and HKP server specifications. It may lack
   meaning initially for some records, but is reserved for later use.
   Some plans for state:

    - Flagging a key as garbage, spam, or in general disuse.
    - Limiting the visibility or distribution of the key, subkey or signature.

   For example, a public keyserver exposes UID certifications which can be easily
   harvested to reproduce a social graph. prlpks could hide these certifications
   to unauthenticated queries, and only reveal them to requests that are signed with the
   OpenPGP public keys that are actually a part of the social graph.

   packet
   ~~~~~~
   The original OpenPGP binary packet data is stored verbatim in the database.
   All other columns that copy the content contained in packets exist for the purpose
   of query convenience and performance. The prlpks server should assert consistency
   between these on insert/update, as well as in an integrity verification utility.

*/

const Cr_openpgp_pubkey = `
CREATE TABLE IF NOT EXISTS openpgp_pubkey (
-----------------------------------------------------------------------
-- Full public key fingerprint, LSB-to-MSB, lowercased hex
uuid TEXT NOT NULL,
-- Public key creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- Public key expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '9999-12-31 23:59:59+00',
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Creation time of this public key fingerprint in the database
ctime TIMESTAMP WITH TIME ZONE NOT NULL,
-- Last-modified time of this public key fingerprint in the database
mtime TIMESTAMP WITH TIME ZONE NOT NULL,
-- MD5 digest of the entire public key contents, compatible with SKS
md5 TEXT NOT NULL,
-- SHA256 digest of the entire public key contents, using same method
sha256 TEXT NOT NULL,
-- Reference to a revocation on this primary key
revsig_uuid TEXT,
-- Reference to the primary User ID
primary_uid TEXT,
-- Reference to the primary User Attribute
primary_uat TEXT,
-----------------------------------------------------------------------
-- Public-key algorithm, RFC 4880, Section 9.1
algorithm INTEGER NOT NULL,
-- Public-key bit length
bit_len INTEGER NOT NULL,
-----------------------------------------------------------------------
-- Unsupported key material aggregated here
unsupp bytea
)`

const Cr_openpgp_sig = `
CREATE TABLE IF NOT EXISTS openpgp_sig (
-----------------------------------------------------------------------
-- Scope- and content-unique identifer
uuid TEXT NOT NULL,
-- Signature creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- Signature expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '9999-12-31 23:59:59+00',
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Signature type, RFC 4880, Section 5.2.1
sig_type INTEGER NOT NULL,
-- Key ID (16-character prefix of the public key rfingerprint)
signer TEXT NOT NULL,
-- Matched reference to the signer in *this* database, if found
signer_uuid TEXT,
-- Reference to a revocation on this signature, if any
revsig_uuid TEXT
)`

const Cr_openpgp_subkey = `
CREATE TABLE IF NOT EXISTS openpgp_subkey (
-----------------------------------------------------------------------
-- Sub-key public key fingerprint, LSB-to-MSB, lowercased hex
uuid TEXT NOT NULL,
-- Public key creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- Public key expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '9999-12-31 23:59:59+00',
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Primary public key to which the subkey belongs
pubkey_uuid TEXT NOT NULL,
-- Reference to a revocation signature on this sub key, if any
revsig_uuid TEXT,
-----------------------------------------------------------------------
-- Public-key algorithm, RFC 4880, Section 9.1
algorithm INTEGER NOT NULL,
-- Public-key bit length
bit_len INTEGER NOT NULL
)`

const Cr_openpgp_uid = `
CREATE TABLE IF NOT EXISTS openpgp_uid (
-----------------------------------------------------------------------
-- Scope- and content-unique identifer
uuid TEXT NOT NULL,
-- User ID creation timestamp. Since this packet lacks a field
-- for creation time, the earliest self-signature timestamp is used here.
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- User ID expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '9999-12-31 23:59:59+00',
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-----------------------------------------------------------------------
-- Public key to which this identity belongs
pubkey_uuid TEXT NOT NULL,
-- Reference to a revocation signature on this identity, if any
revsig_uuid TEXT,
-----------------------------------------------------------------------
-- Original text of the user identity string
keywords TEXT NOT NULL,
-- Tokenized, fulltext searchable index
keywords_fulltext tsvector NOT NULL
)`

const Cr_openpgp_uat = `
CREATE TABLE IF NOT EXISTS openpgp_uat (
-----------------------------------------------------------------------
-- Scope- and content-unique identifer
uuid TEXT NOT NULL,
-- User attribute creation timestamp. Since this packet lacks a field
-- for creation time, the earliest self-signature timestamp is used here.
creation TIMESTAMP WITH TIME ZONE NOT NULL,
-- User attribute expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '9999-12-31 23:59:59+00',
-- State flag for this record
state INTEGER NOT NULL DEFAULT 0,
-- Binary contents of the OpenPGP packet
packet bytea,
-----------------------------------------------------------------------
-- Public key to which this identity belongs
pubkey_uuid TEXT,
-- Reference to a revocation signature on this identity, if any
revsig_uuid TEXT
)`

const Cr_openpgp_pubkey_sig = `
CREATE TABLE IF NOT EXISTS openpgp_pubkey_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Public key that is signed
pubkey_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL
)`

const Cr_openpgp_subkey_sig = `
CREATE TABLE IF NOT EXISTS openpgp_subkey_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Public key to which the subkey belongs
pubkey_uuid TEXT NOT NULL,
-- Sub key that is signed
subkey_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL
)`

const Cr_openpgp_uid_sig = `
CREATE TABLE IF NOT EXISTS openpgp_uid_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Public key to which the UID
pubkey_uuid TEXT NOT NULL,
-- User ID that is signed
uid_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL
)`

const Cr_openpgp_uat_sig = `
CREATE TABLE IF NOT EXISTS openpgp_uat_sig (
-----------------------------------------------------------------------
-- Universally-unique identifer
uuid TEXT NOT NULL,
-- Public key to which the UID
pubkey_uuid TEXT NOT NULL,
-- UID that is signed
uat_uuid TEXT NOT NULL,
-- Signature
sig_uuid TEXT NOT NULL
)`

const Cr_pks_stat = `
CREATE TABLE IF NOT EXISTS pks_status (
-----------------------------------------------------------------------
-- Scope- and content-unique identifer
uuid TEXT NOT NULL,
-- User ID creation timestamp
creation TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
-- User ID expiration timestamp (if any)
expiration TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '9999-12-31 23:59:59+00',
-- State flag for this record. Nonzero disables.
state INTEGER NOT NULL DEFAULT 0,
-----------------------------------------------------------------------
-- Email address receiving PKS mail from this host
email_addr TEXT NOT NULL,
-- Last sync timestamp for this address
last_sync TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
-----------------------------------------------------------------------
PRIMARY KEY (uuid),
UNIQUE (email_addr)
)`

//PRC EDIT Start
const Cr_verify_email = `
CREATE TABLE IF NOT EXISTS verify_email (
-----------------------------------------------------------------------
-- Scope- and content-unique identifer
req_email TEXT NOT NULL,
-- Sha256 Hash of the key kto check weather key has been changed since last request
hash_pubkey TEXT NOT NULL,
-- Binary contents of the OpenPGP packet
packet bytea NOT NULL,
-- otl_hash Salted Hash with random input
otl_hash TEXT NOT NULL,
-- Verification Request creation timestamp
req_time TIMESTAMP WITH TIME ZONE NOT NULL,
-- OTL Verification timestamp
veri_time TIMESTAMP WITH TIME ZONE,
-- OTL_Hash Expiration time (creation Time + 2 days)
expi_time TIMESTAMP WITH TIME ZONE NOT NULL,
--Weather verified or not Boolean
is_verified BOOLEAN NOT NULL,
-- armored text of hkp/add request
key_text TEXT NOT NULL,
-- Reference to the RFC 4880 ID (Fingerprint) of requested public key
pubkey_id TEXT NOT NULL,
--Operation,weather otl is being called for addition or deletion
operation SMALLINT NOT NULL,
----------------------------
PRIMARY KEY (hash_pubkey)

)`

//-- Not yet Decided  UNIQUE (otl_hash)
//PRC EDIT Stop

var CreateTablesSql []string = []string{
	Cr_openpgp_pubkey,
	Cr_openpgp_sig,
	Cr_openpgp_subkey,
	Cr_openpgp_uid,
	Cr_openpgp_uat,
	Cr_openpgp_pubkey_sig,
	Cr_openpgp_subkey_sig,
	Cr_openpgp_uid_sig,
	Cr_openpgp_uat_sig,
	Cr_pks_stat,
	//ADDED BY PRC
	Cr_verify_email}

//PRC END

var Cr_openpgp_pubkey_constraints []string = []string{
	`ALTER TABLE openpgp_pubkey ADD CONSTRAINT openpgp_pubkey_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_pubkey ADD CONSTRAINT openpgp_pubkey_md5 UNIQUE (md5);`,
	`ALTER TABLE openpgp_pubkey ADD CONSTRAINT openpgp_pubkey_sha256 UNIQUE (sha256);`}

var Cr_openpgp_sig_constraints []string = []string{
	`ALTER TABLE openpgp_sig ADD CONSTRAINT openpgp_sig_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_pubkey ADD CONSTRAINT openpgp_pubkey_revsig_fk
	FOREIGN KEY (revsig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_sig ADD CONSTRAINT openpgp_sig_signer_fk FOREIGN KEY (signer_uuid)
	REFERENCES openpgp_pubkey(uuid) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_sig ADD CONSTRAINT openpgp_sig_rev_fk FOREIGN KEY (revsig_uuid)
	REFERENCES openpgp_sig(uuid) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`}

var Cr_openpgp_subkey_constraints []string = []string{
	`ALTER TABLE openpgp_subkey ADD CONSTRAINT openpgp_subkey_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_subkey ADD CONSTRAINT openpgp_subkey_pubkey_fk
	FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_subkey ADD CONSTRAINT openpgp_subkey_rev_fk
	FOREIGN KEY (revsig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`CREATE INDEX openpgp_subkey_pubkey ON openpgp_subkey (pubkey_uuid);`}

var Cr_openpgp_uid_constraints []string = []string{
	`ALTER TABLE openpgp_uid ADD CONSTRAINT openpgp_uid_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_uid ADD CONSTRAINT openpgp_uid_pubkey_fk
	FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_pubkey ADD CONSTRAINT openpgp_pubkey_primary_uid_fk
	FOREIGN KEY (primary_uid) REFERENCES openpgp_uid(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_uid ADD CONSTRAINT openpgp_uid_rev_fk
	FOREIGN KEY (revsig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`CREATE INDEX openpgp_uid_pubkey ON openpgp_uid (pubkey_uuid);`,
	`CREATE INDEX openpgp_uid_fulltext_idx ON openpgp_uid USING gin(keywords_fulltext);`}

var Cr_openpgp_uat_constraints []string = []string{
	`ALTER TABLE openpgp_uat ADD CONSTRAINT openpgp_uat_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_uat ADD CONSTRAINT openpgp_uat_pubkey_fk
	FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_pubkey ADD CONSTRAINT openpgp_pubkey_primary_uat_fk
	FOREIGN KEY (primary_uat) REFERENCES openpgp_uat(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_uat ADD CONSTRAINT openpgp_uat_rev_fk
	FOREIGN KEY (revsig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`CREATE INDEX openpgp_uat_pubkey ON openpgp_uat (pubkey_uuid);`}

var Cr_openpgp_pubkey_sig_constraints []string = []string{
	`ALTER TABLE openpgp_pubkey_sig ADD CONSTRAINT openpgp_pubkey_sig_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_pubkey_sig ADD CONSTRAINT openpgp_pubkey_sig_unique
	UNIQUE (pubkey_uuid, sig_uuid);`,
	`ALTER TABLE openpgp_pubkey_sig ADD CONSTRAINT openpgp_pubkey_sig_pubkey_fk
	FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_pubkey_sig ADD CONSTRAINT openpgp_pubkey_sig_sig_fk
	FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`}

var Cr_openpgp_subkey_sig_constraints []string = []string{
	`ALTER TABLE openpgp_subkey_sig ADD CONSTRAINT openpgp_subkey_sig_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_subkey_sig ADD CONSTRAINT openpgp_subkey_sig_unique
	UNIQUE (subkey_uuid, sig_uuid);`,
	`ALTER TABLE openpgp_subkey_sig ADD CONSTRAINT openpgp_subkey_sig_pubkey_fk
	FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_subkey_sig ADD CONSTRAINT openpgp_subkey_sig_subkey_fk
	FOREIGN KEY (subkey_uuid) REFERENCES openpgp_subkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_subkey_sig ADD CONSTRAINT openpgp_subkey_sig_sig_fk
	FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`}

var Cr_openpgp_uid_sig_constraints []string = []string{
	`ALTER TABLE openpgp_uid_sig ADD CONSTRAINT openpgp_uid_sig_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_uid_sig ADD CONSTRAINT openpgp_uid_sig_unique
	UNIQUE (uid_uuid, sig_uuid);`,
	`ALTER TABLE openpgp_uid_sig ADD CONSTRAINT openpgp_uid_sig_pubkey_fk
	FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_uid_sig ADD CONSTRAINT openpgp_uid_sig_uid_fk
	FOREIGN KEY (uid_uuid) REFERENCES openpgp_uid(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_uid_sig ADD CONSTRAINT openpgp_uid_sig_sig_fk
	FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`}

var Cr_openpgp_uat_sig_constraints []string = []string{
	`ALTER TABLE openpgp_uat_sig ADD CONSTRAINT openpgp_uat_sig_pk PRIMARY KEY (uuid);`,
	`ALTER TABLE openpgp_uat_sig ADD CONSTRAINT openpgp_uat_sig_unique
	UNIQUE (uat_uuid, sig_uuid);`,
	`ALTER TABLE openpgp_uat_sig ADD CONSTRAINT openpgp_uat_sig_pubkey_fk
	FOREIGN KEY (pubkey_uuid) REFERENCES openpgp_pubkey(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_uat_sig ADD CONSTRAINT openpgp_uat_sig_uat_fk
	FOREIGN KEY (uat_uuid) REFERENCES openpgp_uat(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`,
	`ALTER TABLE openpgp_uat_sig ADD CONSTRAINT openpgp_uat_sig_sig_fk
	FOREIGN KEY (sig_uuid) REFERENCES openpgp_sig(uuid)
	ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;`}

var CreateConstraintsSql [][]string = [][]string{
	Cr_openpgp_pubkey_constraints,
	Cr_openpgp_sig_constraints,
	Cr_openpgp_subkey_constraints,
	Cr_openpgp_uid_constraints,
	Cr_openpgp_uat_constraints,
	Cr_openpgp_pubkey_sig_constraints,
	Cr_openpgp_subkey_sig_constraints,
	Cr_openpgp_uid_sig_constraints,
	Cr_openpgp_uat_sig_constraints}

const dedupTemplate = `
{{define "cols"}}{{/*
*/}}{{range $i, $colname := .UniqueColumns}}{{if $i}},{{end}}{{$colname}}{{end}}{{/*
*/}}{{end}}{{/*
*/}}{{define "sql"}}{{/*
*/}}CREATE TABLE dedup_{{.TableName}} AS
	SELECT DISTINCT ON ({{template "cols" .}}) * FROM {{.TableName}};
DROP TABLE {{.TableName}};
ALTER TABLE dedup_{{.TableName}} RENAME TO {{.TableName}};{{/*
*/}}{{end}}{{template "sql" .}}`

type dedup struct {
	TableName     string
	UniqueColumns []string
}

var dedups []dedup = []dedup{
	dedup{"openpgp_pubkey", []string{"uuid"}},
	dedup{"openpgp_sig", []string{"uuid"}},
	dedup{"openpgp_subkey", []string{"uuid"}},
	dedup{"openpgp_uid", []string{"uuid"}},
	dedup{"openpgp_uat", []string{"uuid"}},
	dedup{"openpgp_pubkey_sig", []string{"uuid"}},
	dedup{"openpgp_pubkey_sig", []string{"pubkey_uuid", "sig_uuid"}},
	dedup{"openpgp_subkey_sig", []string{"uuid"}},
	dedup{"openpgp_subkey_sig", []string{"subkey_uuid", "sig_uuid"}},
	dedup{"openpgp_uid_sig", []string{"uuid"}},
	dedup{"openpgp_uid_sig", []string{"uid_uuid", "sig_uuid"}},
	dedup{"openpgp_uat_sig", []string{"uuid"}},
	dedup{"openpgp_uat_sig", []string{"uat_uuid", "sig_uuid"}}}

var DeleteDuplicatesSql []string

func init() {
	t := template.Must(template.New("DeleteDuplicates").Parse(dedupTemplate))
	var sql []string
	var err error
	for _, dedup := range dedups {
		var out bytes.Buffer
		if err = t.Execute(&out, dedup); err != nil {
			panic(err)
		}
		sql = append(sql, out.String())
	}
	DeleteDuplicatesSql = sql
}

var Dr_openpgp_pubkey_constraints []string = []string{
	`ALTER TABLE openpgp_pubkey DROP CONSTRAINT openpgp_pubkey_pk;`,
	`ALTER TABLE openpgp_pubkey DROP CONSTRAINT openpgp_pubkey_md5;`,
	`ALTER TABLE openpgp_pubkey DROP CONSTRAINT openpgp_pubkey_sha256;`,
	`ALTER TABLE openpgp_pubkey DROP CONSTRAINT openpgp_pubkey_primary_uid_fk;`,
	`ALTER TABLE openpgp_pubkey DROP CONSTRAINT openpgp_pubkey_primary_uat_fk;`,
	`ALTER TABLE openpgp_pubkey DROP CONSTRAINT openpgp_pubkey_revsig_fk;`}

var Dr_openpgp_sig_constraints []string = []string{
	`ALTER TABLE openpgp_sig DROP CONSTRAINT openpgp_sig_pk;`,
	`ALTER TABLE openpgp_sig DROP CONSTRAINT openpgp_sig_signer_fk;`,
	`ALTER TABLE openpgp_sig DROP CONSTRAINT openpgp_sig_rev_fk;`}

var Dr_openpgp_subkey_constraints []string = []string{
	`ALTER TABLE openpgp_subkey DROP CONSTRAINT openpgp_subkey_pk;`,
	`ALTER TABLE openpgp_subkey DROP CONSTRAINT openpgp_subkey_pubkey_fk;`,
	`ALTER TABLE openpgp_subkey DROP CONSTRAINT openpgp_subkey_rev_fk;`}

var Dr_openpgp_uid_constraints []string = []string{
	`ALTER TABLE openpgp_uid DROP CONSTRAINT openpgp_uid_pk;`,
	`ALTER TABLE openpgp_uid DROP CONSTRAINT openpgp_uid_pubkey_fk;`,
	`ALTER TABLE openpgp_uid DROP CONSTRAINT openpgp_uid_rev_fk;`,
	`DROP INDEX openpgp_uid_fulltext_idx;`}

var Dr_openpgp_uat_constraints []string = []string{
	`ALTER TABLE openpgp_uat DROP CONSTRAINT openpgp_uat_pk;`,
	`ALTER TABLE openpgp_uat DROP CONSTRAINT openpgp_uat_pubkey_fk;`,
	`ALTER TABLE openpgp_uat DROP CONSTRAINT openpgp_uat_rev_fk;`}

var Dr_openpgp_pubkey_sig_constraints []string = []string{
	`ALTER TABLE openpgp_pubkey_sig DROP CONSTRAINT openpgp_pubkey_sig_pk;`,
	`ALTER TABLE openpgp_pubkey_sig DROP CONSTRAINT openpgp_pubkey_sig_unique;`,
	`ALTER TABLE openpgp_pubkey_sig DROP CONSTRAINT openpgp_pubkey_sig_pubkey_fk;`,
	`ALTER TABLE openpgp_pubkey_sig DROP CONSTRAINT openpgp_pubkey_sig_sig_fk;`}

var Dr_openpgp_subkey_sig_constraints []string = []string{
	`ALTER TABLE openpgp_subkey_sig DROP CONSTRAINT openpgp_subkey_sig_pk;`,
	`ALTER TABLE openpgp_subkey_sig DROP CONSTRAINT openpgp_subkey_sig_unique;`,
	`ALTER TABLE openpgp_subkey_sig DROP CONSTRAINT openpgp_subkey_sig_pubkey_fk;`,
	`ALTER TABLE openpgp_subkey_sig DROP CONSTRAINT openpgp_subkey_sig_subkey_fk;`,
	`ALTER TABLE openpgp_subkey_sig DROP CONSTRAINT openpgp_subkey_sig_sig_fk;`}

var Dr_openpgp_uid_sig_constraints []string = []string{
	`ALTER TABLE openpgp_uid_sig DROP CONSTRAINT openpgp_uid_sig_pk;`,
	`ALTER TABLE openpgp_uid_sig DROP CONSTRAINT openpgp_uid_sig_unique;`,
	`ALTER TABLE openpgp_uid_sig DROP CONSTRAINT openpgp_uid_sig_pubkey_fk;`,
	`ALTER TABLE openpgp_uid_sig DROP CONSTRAINT openpgp_uid_sig_uid_fk;`,
	`ALTER TABLE openpgp_uid_sig DROP CONSTRAINT openpgp_uid_sig_sig_fk;`}

var Dr_openpgp_uat_sig_constraints []string = []string{
	`ALTER TABLE openpgp_uat_sig DROP CONSTRAINT openpgp_uat_sig_pk;`,
	`ALTER TABLE openpgp_uat_sig DROP CONSTRAINT openpgp_uat_sig_unique;`,
	`ALTER TABLE openpgp_uat_sig DROP CONSTRAINT openpgp_uat_sig_pubkey_fk;`,
	`ALTER TABLE openpgp_uat_sig DROP CONSTRAINT openpgp_uat_sig_uat_fk;`,
	`ALTER TABLE openpgp_uat_sig DROP CONSTRAINT openpgp_uat_sig_sig_fk;`}

var DropConstraintsSql [][]string = [][]string{
	Dr_openpgp_pubkey_constraints,
	Dr_openpgp_sig_constraints,
	Dr_openpgp_subkey_constraints,
	Dr_openpgp_uid_constraints,
	Dr_openpgp_uat_constraints,
	Dr_openpgp_pubkey_sig_constraints,
	Dr_openpgp_subkey_sig_constraints,
	Dr_openpgp_uid_sig_constraints,
	Dr_openpgp_uat_sig_constraints}
