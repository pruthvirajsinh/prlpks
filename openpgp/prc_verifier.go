// prc_verifier
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
	//"code.google.com/p/go.crypto/openpgp/armor"
	//"code.google.com/p/go.crypto/openpgp/packet"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	//"github.com/jmoiron/sqlx"
	. "github.com/pruthvirajsinh/prlpks/errors"
	"io"
	"strings"
	"time"
)

const (
	OTLVerified         int = 1
	OTLNotFound         int = 2
	OTLExpired          int = 3
	OTLNotVerified      int = 4
	OTLAlereadyVerified int = 5
	OTLNewOtlMade       int = 6
	ErrorSendingMail    int = 7
)

const ( //To create Email
	subject   string = "PKS:Please verify the request"
	otlPrefix string = "http://"
	otlMid    string = "/prc/verify?otl="
)

type Veri_data struct {
	//Database values
	//otl_hash,req_email,req_time,verify_time,verified,req_pubkey
	Req_email   string    `db:"req_email"`   // immutable
	Hash_pubkey string    `db:"hash_pubkey"` //immutable
	Packet      []byte    `db:"packet"`      // immutable
	Otl_hash    string    `db:"otl_hash"`    // mutable
	Req_time    time.Time `db:"req_time"`    // immutable
	Veri_time   time.Time `db:"veri_time"`   // mutable
	Expi_time   time.Time `db:"expi_time"`   //immutable
	Is_verified bool      `db:"is_verified"` // mutable
	Key_text    string    `db:"key_text"`    // immutable
	Pubkey_id   string    `db:"pubkey_id"`   //immutable
	Operation   int16     `db:"operation"`   //1 for add , 2 for delete
}

const ExpInDays int = 2

/*
op 1=add
op 2=delete
Verification process
			DONE 1. extract email ID from go.crypto/openpgp/packet struct userID
			DONE 2. lookup in to db for (e-mail,sha256_key) pair,if verified return true
			DONE 3. generate a random otl_hash for key
			DONE 4. add in to mail_verify db(e-mail,sha256_key,otl_hash,req_time,verify_time,verified,pubkey_packet,pub_key_ID)
			DONE	 5. call sendmail with otl and email
*/
func (w *Worker) Verify(eMail string, keytext string, req_Pubkey Pubkey, op int16) (isVerified bool, resultCode int) {

	log.Println(">>>>>>>>>>>>", eMail, "<<<<<<<<<<<<<<")
	log.Println("Verifier.go:Time of request", time.Now().Format(time.StampNano))
	/*TODO 2 and 4. verify in db
	If db has primary key pair
			--If verified && Req_time< ver_time
				return true
			--Else Email has not been verified yet but a request is already made
				--If now-(Req_time_old_request_from_db) > 2days
					delete old request and generate new request and send mail
				--Else
					return false
	Else db has no primary key pair
			Generate otl,save in db and send e-mail
			return false
	*/

	//Create and populate Veri_data
	verif_req_data := new(Veri_data)
	verif_req_data.Req_email = eMail
	verif_req_data.Packet = req_Pubkey.Packet
	verif_req_data.Key_text = keytext
	verif_req_data.Hash_pubkey = req_Pubkey.Sha256
	verif_req_data.Pubkey_id = req_Pubkey.Fingerprint()
	verif_req_data.Is_verified = false
	verif_req_data.Operation = op
	// otl_hash and 3 timestamps are still null
	ver, result_code := w.verifyOTL(verif_req_data)
	if result_code != 0 {
		if result_code == OTLNotFound {
			log.Println("OTL NOT FOUND!!")
			w.deleteOTL(verif_req_data) //Delete any previous OTL with same key hash
			if err := w.insertOTL(verif_req_data); err == nil {
				result_code = OTLNewOtlMade
			} else {
				result_code = ErrorSendingMail
			}

		} else if result_code == OTLExpired {
			log.Println("OTL Expired!!")
			w.handleExpiredOTL(verif_req_data)
			if err := w.insertOTL(verif_req_data); err == nil {
				result_code = OTLNewOtlMade
			}

		} else if result_code == OTLNotVerified {
			log.Println("OTL Not Verified!!")
		}
	} else {
		if ver {
			log.Println("OTL Exists and is verified")
			//verif_req_data.Is_verified = ver
		}
	}
	isVerified = ver
	resultCode = result_code
	return
}

const SaltSize = 16

func saltedHash(secret string) []byte {
	buf := make([]byte, SaltSize, SaltSize+(crypto.SHA256.Size()))
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Errorf("random read failed: %v", err))
	}
	h := crypto.SHA256.New()
	h.Write(buf)

	h.Write([]byte(secret))
	return h.Sum(buf)
}

func (w *Worker) insertOTL(veri *Veri_data) (err error) {
	/*
	    Else db has no primary key pair
	   			Generate otl,save in db and send e-mail
	   			return false
	*/
	//Check weather a key with same email exists on the server already,if yes replace it on OTL verification

	veri.Otl_hash = hex.EncodeToString(saltedHash(veri.Key_text + veri.Hash_pubkey))
	log.Println("verifier.go:otl_hash of above request is:", veri.Otl_hash)
	log.Println("verifier.go:Calling Send mail with", veri.Req_email, veri.Otl_hash)
	//OTL Format
	//http://host/prc/verify?otl=otlhash
	ownAuth, err1 := GetOwnAuthority()
	if err1 != nil {
		err = err1
		return
	}
	ownAddr := ownAuth.HkpAddr
	messageOTL := otlPrefix + ownAddr + otlMid + veri.Otl_hash
	var message string

	if veri.Operation == int16(1) {
		resKeys, err := w.LookupKeys(veri.Req_email, 2)
		if err == ErrKeyNotFound || len(resKeys) <= 0 { //No key found by Email
		} else { //Replcaes Key
			message = "	* A key with same email already exists on the server! Opening the following link will REPLACE the existing key having id = " +
				strings.ToUpper(resKeys[0].KeyId()) + ".		\n"
		}
	} else if veri.Operation == int16(2) {
		message = "	* Opening the following link will DELETE the existing key having id = " +
			strings.ToUpper(veri.Pubkey_id) + ".		\n"
	}

	message += " <a href=" + messageOTL + ">  " + messageOTL + "  </a>"
	message += "\n	If you are not able to click above link then copy and paste it in the address bar of the browser to open it"
	err = SendEmail(veri.Req_email, subject, message)
	if err != nil {
		fmt.Println(err)
		log.Println(err)
		return
	} else {
		//Insert into DB
		veri.Req_time = time.Now()
		//func (t Time) AddDate(years int, months int, days int) Time
		veri.Expi_time = veri.Req_time.AddDate(0, 0, ExpInDays)
		//tx := w.db.MustBegin()

		if _, err = w.Begin(); err != nil {
			log.Println("Insert OTL:", err)
			return
		}

		w.tx.Execl(`INSERT INTO verify_email 
		(req_email, hash_pubkey, packet, otl_hash,
		req_time,veri_time,expi_time,
		is_verified,key_text,pubkey_id,operation) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,$10,$11)`,
			veri.Req_email, veri.Hash_pubkey, veri.Packet, veri.Otl_hash,
			veri.Req_time, veri.Veri_time, veri.Expi_time,
			veri.Is_verified, veri.Key_text, veri.Pubkey_id, veri.Operation)

		err = w.Commit()
		if err != nil {
			log.Println("Insert OTL:", err)
			return
		}
	}
	return
}

func (w *Worker) verifyOTL(veri *Veri_data) (is_verified bool, result_code int) {

	/*
		If db has primary key pair
				--If verified && Req_time< ver_time
					return true
				--Else Email has not been verified yet but a request is already made
					--If now-(Req_time_old_request_from_db) > 2days
						delete old request and generate new request and send mail
					--Else
						return false
	*/
	Temp_veri := []Veri_data{}

	w.db.Select(&Temp_veri, `SELECT * FROM verify_email 
	WHERE hash_pubkey=$1 
	AND (req_email=$2 
	AND pubkey_id=$3 AND operation=$4)`, veri.Hash_pubkey, veri.Req_email, veri.Pubkey_id, veri.Operation)

	if len(Temp_veri) == 0 {
		result_code = OTLNotFound
		veri.Is_verified = false
	} else {
		log.Println("Sha256 matched!!", Temp_veri[0].Hash_pubkey == veri.Hash_pubkey)
		log.Println("key id matched!!", Temp_veri[0].Pubkey_id == veri.Pubkey_id)
		if Temp_veri[0].Hash_pubkey == veri.Hash_pubkey && Temp_veri[0].Pubkey_id == veri.Pubkey_id {
			*veri = Temp_veri[0]
			if veri.Expi_time.Before(time.Now()) {
				result_code = OTLExpired
				w.handleExpiredOTL(veri)
				veri.Is_verified = false
			} else if veri.Is_verified != true {
				result_code = OTLNotVerified
			}
		}
	}

	is_verified = veri.Is_verified
	return
}
func (w *Worker) handleExpiredOTL(veri *Veri_data) (err error) {
	//Delete row of hash_pubkey
	//tx := w.db.MustBegin()

	if _, err = w.Begin(); err != nil {
		log.Println("Handle Expire OTL:", err)
		return
	}
	w.tx.Execl(`DELETE FROM verify_email
				WHERE hash_pubkey = $1`, veri.Hash_pubkey)
	if err = w.Commit(); err != nil {
		log.Println("Handle Expire OTL:", err)

		return
	}

	//err = tx.Commit()

	return
}
func (w *Worker) deleteOTL(veri *Veri_data) (err error) {
	//Delete row of hash_pubkey
	//tx := w.db.MustBegin()

	if _, err = w.Begin(); err != nil {
		log.Println("Delete OTL:", err)
		return
	}

	w.tx.Execl(`DELETE FROM verify_email
				WHERE hash_pubkey = $1`, veri.Hash_pubkey)
	w.tx.Execl(`DELETE FROM verify_email
				WHERE pubkey_id = $1`, veri.Pubkey_id)
	//err = tx.Commit()
	if err = w.Commit(); err != nil {
		log.Println("Delete OTL:", err)
		return
	}

	return
}

/*		TODO: 1.handle otl clicks in otl_handler
//2.verify from mail_verify db
//3. Sign the key with servers key
//4. Store the signed key in tmp db
//3.then again call add with new key
*/

/*
const Cr_verify_email = `
CREATE TABLE IF NOT EXISTS verify_email (
-----------------------------------------------------------------------
-- Scope- and content-unique identifer
req_email TEXT NOT NULL,
-- Sha256 Hash of the key to check weather key has been changed since last request
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
----------------------------
PRIMARY KEY (hash_pubkey)

)`
*/

/*
<<<lookup>>>
rows, err := w.db.Queryx(fmt.Sprintf(`
SELECT uuid FROM openpgp_pubkey WHERE uuid %s
UNION
SELECT pubkey_uuid FROM openpgp_subkey WHERE uuid %s`, compareOp, compareOp), rKeyId)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	} else if err != nil {
		return
	}

<<< Insert>>>
tx := db.MustBegin()
    tx.Execl("INSERT INTO person (first_name, last_name, email) VALUES ($1, $2, $3)", "Jason", "Moiron", "jmoiron@jmoiron.net")
tx.Commit()

    // Query the database, storing results in a []Person (wrapped in []interface{})
    people := []Person{}
    db.Select(&people, "SELECT * FROM person ORDER BY first_name ASC")
    jason, john := people[0], people[1]

*/
