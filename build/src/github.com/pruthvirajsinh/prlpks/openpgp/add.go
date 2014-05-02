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
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/rand"
	"encoding/ascii85"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	//	"strings"
	"time"
	//"code.google.com/p/go.crypto/openpgp"
	. "github.com/pruthvirajsinh/prlpks/errors"
	"github.com/pruthvirajsinh/prlpks/hkp"
)

// KeyChangeChan channels are used for sending and receiving
// key changes resulting from adding a new key or merging
// updates into an existing one.

type KeyChangeChan chan *KeyChange

// Add responds to /pks/add HKP requests.
func (w *Worker) Add(a *hkp.Add) {
	// Parse armored keytext
	var changes []*KeyChange
	var readErrors []*ReadKeyResult
	// Check and decode the armor
	armorBlock, err := armor.Decode(bytes.NewBufferString(a.Keytext))
	if err != nil {
		a.Response() <- &ErrorResponse{err}
		return
	}

	for readKey := range ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			readErrors = append(readErrors, readKey)
		} else {
			log.Println("add.go: Found a key from request!! = ", readKey.Pubkey.KeyId())
			//SignPubKeyPKS(*readKey.Pubkey)
			//First Check weather we are the authority for it
			underAuth := IsUnderAuth(*readKey.Pubkey)
			if underAuth != nil {
				change1 := &KeyChange{}
				change1.Type = NotInOurAuthority
				change1.ChangeMessage = underAuth.Error()
				changes = append(changes, change1)
				log.Println(underAuth.Error())
			} else {

				//Checked weather its under our own authority

				if readKey.Pubkey.Sha256 == a.ShaOfTarget || len(a.ShaOfTarget) != 64 {
					//Extract Email
					usrID := readKey.Pubkey.primaryUid
					userEmail := usrID.UserId.Email
					//Email extracted
					req_PubKey := readKey.Pubkey
					reqChanges := w.FindChanges(readKey.Pubkey)
					isVerified := false
					var otlState int
					if reqChanges.Type == KeyAdded {
						//Key not found hence new key added
						log.Println("add.go:Request has New Key (ID): ", req_PubKey.Fingerprint())

						isVerified, otlState = w.Verify(userEmail, a.Keytext, *req_PubKey, int16(1))
						log.Println("add.go:Is Requested Key Verified??: ", isVerified)

					} else if reqChanges.Type == KeyModified {
						//key will be changed/updated with new contents
						log.Println("add.go:Request Modifies key (ID): ", req_PubKey.Fingerprint())

						isVerified, otlState = w.Verify(userEmail, a.Keytext, *req_PubKey, int16(1))
						log.Println("add.go:Is Requested Key Verified??: ", isVerified)
					} else if reqChanges.Type == KeyNotChanged {
						log.Println("add.go:request doesnt make change to key(id) : ", req_PubKey.Fingerprint())

						w.notifyChange(reqChanges)
						changes = append(changes, reqChanges)
						a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
						return
					}

					if isVerified {
						if reqChanges.Type != KeyNotChanged {
							//If key is verified then call upsert as
							//it will eventually insert data in to db
							log.Println("add.go:Key Verified...")
							//Key verified hence add signature of PKS
							//Check weather a key with same email exists or not.
							repKeys, err := w.LookupKeys(userEmail, 2)
							replacesKey := false
							if err == ErrKeyNotFound || len(repKeys) <= 0 { //No key found by Email
								replacesKey = false
							} else {
								replacesKey = true
							}

							//Replace End

							//Signing Start
							signed_Key, err := SignKeyAfterVerification(a.Keytext)
							if err != nil {
								log.Println("Error signing key ", err)
								a.Response() <- &ErrorResponse{err}
								return
							}
							armorBlock, err := armor.Decode(bytes.NewBufferString(signed_Key))
							if err != nil {
								log.Println("decoding signed key ", err)
								a.Response() <- &ErrorResponse{err}
								return
							}

							for readKey := range ReadKeys(armorBlock.Body) {
								if readKey.Error != nil {
									readErrors = append(readErrors, readKey)
								} else {

									if _, err = w.Begin(); err != nil {
										a.Response() <- &ErrorResponse{err}
										return
									}
									change := w.UpsertKey(readKey.Pubkey)
									if err = w.Commit(); err != nil {
										a.Response() <- &ErrorResponse{err}
										return
									}
									//Signing END
									if change.Error != nil {
										log.Printf("Error updating key [%s]: %v\n", readKey.Pubkey.Fingerprint(),
											change.Error)
									} else {
										if replacesKey {
											//Delete Old key
											if _, err = w.Begin(); err != nil {
												log.Println("replaceDelete", err)
												a.Response() <- &ErrorResponse{err}
												return
											}
											change, err1 := w.deleteKey(repKeys[0])
											if err = w.Commit(); err != nil {
												log.Println("replaceDelete", err)
												a.Response() <- &ErrorResponse{err}
												return
											}

											if err1 != nil {
												log.Println("replaceDelete", err1)
												a.Response() <- &ErrorResponse{err1}
												return
											}

											w.notifyChange(&change)
											changes = append(changes, &change)
										}
									}

									//Notify using changes
									w.notifyChange(change)
									changes = append(changes, change)
								}
							}

						} else {
							w.notifyChange(reqChanges)
							changes = append(changes, reqChanges)
						}
					} else {
						reqChanges.Type = EmailNotVerified
						reqChanges.Fingerprint = ""
						if otlState == OTLNewOtlMade {
							resKeys, err := w.LookupKeys(userEmail, 2)
							replacesKey := false
							if err == ErrKeyNotFound || len(resKeys) <= 0 { //No key found by Email
								replacesKey = false
							} else {
								replacesKey = true
							}

							message := fmt.Sprintf("A verification link has been sent to %s.The link will expire in %d day/s.\n Please check your email.", userEmail, ExpInDays)
							if replacesKey {
								message += "		* A key with same email already exists on the server.If you verify above request it will replace the key with id " +
									strings.ToUpper(resKeys[0].KeyId())
							}
							reqChanges.ChangeMessage = message
							log.Println("OTL NOT FOUND!!")

						} else if otlState == OTLExpired {
							reqChanges.ChangeMessage = fmt.Sprintf("The link you have clicked has expired. Please submit your key again.")
							log.Println("OTL Expired!!")

						} else if otlState == OTLNotVerified {
							reqChanges.ChangeMessage = fmt.Sprintf("A request for same key has already been made.Please Check your email %s", userEmail)
							log.Println("OTL Not Verified!!")
						} else if otlState == ErrorSendingMail {
							reqChanges.ChangeMessage = fmt.Sprintf("Unfortunately we were unable to send an e-mail to %s Please Add key after sometime with new request", userEmail)
						}

						changes = append(changes, reqChanges)
					}

					//EDIT END

				}
				a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
				return
			}
			a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
			return
		}
	}
}

// recoverKey responds to public keys recovered from the recon
// protocol.
func (w *Worker) recoverKey(rk *RecoverKey) hkp.Response {
	resp := &RecoverKeyResponse{}
	// Attempt to parse and upsert key

	var pubkeys []*Pubkey
	var err error
	for readKey := range ReadKeys(bytes.NewBuffer(rk.Keytext)) {
		if readKey.Error != nil {
			err = readKey.Error
		} else {
			pubkeys = append(pubkeys, readKey.Pubkey)
		}
	}
	if err != nil {
		return &ErrorResponse{err}
	}
	if len(pubkeys) == 0 {
		return &ErrorResponse{ErrKeyNotFound}
	} else if len(pubkeys) > 1 {
		return &ErrorResponse{ErrTooManyResponses}
	}

	//PRC Start
	//fmt.Println("recoverKey", rk.verifiedDomains)
	email, _ := GetEmailFromPubKey(*pubkeys[0])
	if !IsAuhtorized(email, rk.verifiedDomains) {
		fmt.Print("x")
		return &ErrorResponse{errors.New(fmt.Sprint(email, " Not Verified.Can't Add."))}
	}
	//PRC End

	if _, err = w.Begin(); err != nil {
		return &ErrorResponse{err}
	}
	resp.Change = w.UpsertKey(pubkeys[0])
	if err = w.Commit(); err != nil {
		return &ErrorResponse{err}
	}
	w.notifyChange(resp.Change)
	return resp
}

// ErrSubKeyChanges is an error occurring when attempting to subscribe
// to KeyChange messages on a worker that already has a subscriber.
var ErrSubKeyChanges error = errors.New("Worker already has a key change subscriber")

// SubKeyChanges subscribes a KeyChange channel to receive updates on
// any keys added or updated by this worker.
func (w *Worker) SubKeyChanges(keyChanges KeyChangeChan) error {
	if w.keyChanges != nil {
		return ErrSubKeyChanges
	}
	w.keyChanges = keyChanges
	return nil
}

// notifyChange is used by the worker to broadcast key changes
// to a subscriber, if any.
func (w *Worker) notifyChange(keyChange *KeyChange) {
	if w.keyChanges != nil {
		w.keyChanges <- keyChange
	}
}

// KeyChangeType identifies the type of change that a worker has
// made to a public key.
type KeyChangeType int

const (
	// KeyChangeInvalid indicates that the attempted key change information
	// does not describe an expected, valid event.
	KeyChangeInvalid KeyChangeType = iota
	// KeyNotChanged indicates that a request to update an existing public key
	// did not result in any change or addition of new key material.
	KeyNotChanged KeyChangeType = iota
	// KeyAdded indicates a new key was added to the database.
	KeyAdded KeyChangeType = iota
	// KeyModified indicates that an existing key was updated with new information.
	KeyModified KeyChangeType = iota
	//PRC Start
	//Key is Deleted
	KeyDeleted KeyChangeType = iota
	//Key Replaces current key as emails are same
	KeyReplaced KeyChangeType = iota
	//OTL is not verified yet
	EmailNotVerified KeyChangeType = iota
	//We are not authority for domain of the email,hence can not accept
	NotInOurAuthority KeyChangeType = iota
	//PRC End
)

// KeyChange describes the change made to a public key resulting from
// a /pks/add HKP request.
type KeyChange struct {
	// Fingerprint is the public key fingerprint
	Fingerprint string
	// CurrentMd5 contains the new digest of the key (SKS compatible).
	CurrentMd5 string
	// PreviousMd5 contains the digest of the key prior to update, if any (SKS compatible).
	PreviousMd5 string
	// CurrentSha256 contains the new digest of the key.
	CurrentSha256 string
	// PreviousSha256 contains the digest of the key prior to update, if any.
	PreviousSha256 string
	// Error captures the error that prevented the change from occurring, otherwise nil.
	Error error
	// Type indicates the type of key change that occurred, as indicated by KeyChangeType.
	Type KeyChangeType
	//Message to be displayed at addResponse Screen
	ChangeMessage string
}

// String represents the key change event as a string for diagnostic purposes.
func (kc *KeyChange) String() string {
	w := bytes.NewBuffer(nil)
	var msg string
	switch kc.Type {
	case KeyChangeInvalid:
		msg = fmt.Sprintf("Invalid key change for [%s] could not be processed",
			kc.Fingerprint)
	case KeyAdded:
		msg = fmt.Sprintf("Add key %s, [%s..]", kc.Fingerprint, kc.CurrentSha256[:8])
	case KeyModified:
		msg = fmt.Sprintf("Modify key %s, [%s.. -> %s..]", kc.Fingerprint,
			kc.PreviousSha256[:8], kc.CurrentSha256[:8])
	case KeyNotChanged:
		msg = fmt.Sprintf("No change in key %s", kc.Fingerprint)
	case KeyReplaced:
		msg = kc.ChangeMessage
	case KeyDeleted:
		msg = kc.ChangeMessage
	case EmailNotVerified:
		msg = kc.ChangeMessage
	case NotInOurAuthority:
		msg = kc.ChangeMessage
	}
	w.Write([]byte(msg))
	if kc.Error != nil {
		w.Write([]byte(fmt.Sprintf(": Error: %v", kc.Error)))
	}
	return w.String()
}

func (change *KeyChange) calcType() KeyChangeType {
	if change.CurrentSha256 == "" {
		return KeyChangeInvalid
	} else if change.PreviousSha256 == "" {
		return KeyAdded
	} else if change.PreviousSha256 == change.CurrentSha256 {
		return KeyNotChanged
	}
	return KeyModified
}

func (w *Worker) UpsertKey(key *Pubkey) (change *KeyChange) {
	log.Println("In Upsert,for =", key.KeyId())

	change = &KeyChange{
		Fingerprint:   key.Fingerprint(),
		Type:          KeyChangeInvalid,
		CurrentMd5:    key.Md5,
		CurrentSha256: key.Sha256}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == ErrKeyNotFound {
		change.Type = KeyAdded
	} else if err != nil {
		change.Error = err
		return
	} else {
		change.PreviousMd5 = lastKey.Md5
		change.PreviousSha256 = lastKey.Sha256
		MergeKey(lastKey, key)
		change.CurrentMd5 = lastKey.Md5
		change.CurrentSha256 = lastKey.Sha256
		if change.PreviousMd5 == change.CurrentMd5 && change.PreviousSha256 == change.CurrentSha256 {
			change.Type = KeyNotChanged
		} else {
			change.Type = KeyModified
		}
	}
	if change.CurrentSha256 == "" {
		change.Type = KeyChangeInvalid
	}
	switch change.Type {
	case KeyModified:
		lastKey.Mtime = time.Now()
		if change.Error = w.UpdateKey(lastKey); change.Error == nil {
			w.UpdateKeyRelations(lastKey)
		} else {
			log.Println(change.Error)
		}
	case KeyAdded:
		key.Ctime = time.Now()
		key.Mtime = key.Ctime
		if change.Error = w.InsertKey(key); change.Error == nil {
			w.UpdateKeyRelations(key)
		} else {
			log.Println(change.Error)
		}
	}
	if change.Type != KeyNotChanged {
		log.Println(change)
	}
	return
}

//PRC START : ONLY FINDS changes required g\for incoming request
func (w *Worker) FindChanges(key *Pubkey) (change *KeyChange) {
	change = &KeyChange{
		Fingerprint:   key.Fingerprint(),
		Type:          KeyChangeInvalid,
		CurrentMd5:    key.Md5,
		CurrentSha256: key.Sha256}
	lastKey, err := w.LookupKey(key.Fingerprint())
	if err == ErrKeyNotFound {
		change.Type = KeyAdded
	} else if err != nil {
		change.Error = err
		return
	} else {
		change.PreviousMd5 = lastKey.Md5
		change.PreviousSha256 = lastKey.Sha256
		MergeKey(lastKey, key)
		change.CurrentMd5 = lastKey.Md5
		change.CurrentSha256 = lastKey.Sha256
		if change.PreviousMd5 == change.CurrentMd5 && change.PreviousSha256 == change.CurrentSha256 {
			change.Type = KeyNotChanged
		} else {
			change.Type = KeyModified
		}
	}
	if change.CurrentSha256 == "" {
		change.Type = KeyChangeInvalid
	}
	return
}

func GetEmailFromPubKey(publicKey Pubkey) (email string, err error) {
	if publicKey.primaryUid == nil {
		err = errors.New("No Primary id Found")
		email = ""
		return
	}
	/*
		if len(publicKey.UserIds()) > 1 {
			//fmt.Println("More than one Email found ", publicKey.UserIds())
			msg := ""
			for _, ids := range publicKey.UserIds() {
				msg += ids.UserId.Email + " "
			}
			err = errors.New("Multiple Ids Found " + msg + "Primary ID = " + publicKey.primaryUid.UserId.Email)
			email = ""
			return

		}
	*/
	iD1 := publicKey.primaryUid
	email = iD1.UserId.Email
	return
}

//PRC END
// UpdateKey updates the database to the contents of the given public key.
func (w *Worker) UpdateKey(pubkey *Pubkey) (err error) {
	if err = w.InsertKey(pubkey); err != nil {
		return err
	}
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) (err error) {
		switch r := rec.(type) {
		case *Pubkey:
			_, err := w.db.Execv(`
UPDATE openpgp_pubkey SET
	expiration = $2, state = $3, mtime = $4, md5 = $5, sha256 = $6, unsupp = $7
WHERE uuid = $1`, r.RFingerprint, r.Expiration, r.State, r.Mtime, r.Md5, r.Sha256,
				r.Unsupported)
			if err != nil {
				return err
			}
			signable = r
		case *Subkey:
			_, err := w.tx.Execv(`
UPDATE openpgp_subkey SET expiration = $2, state = $3 WHERE uuid = $1`,
				r.RFingerprint, r.Expiration, r.State)
			if err != nil {
				return err
			}
			signable = r
		case *UserId:
			_, err := w.tx.Execv(`
UPDATE openpgp_uid SET
	creation = $2, expiration = $3, state = $4 WHERE uuid = $1`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State)
			if err != nil {
				return err
			}
			signable = r
		case *UserAttribute:
			_, err := w.tx.Execv(`
UPDATE openpgp_uat SET
	creation = $2, expiration = $3, state = $4 WHERE uuid = $1`,
				r.ScopedDigest, r.Creation, r.Expiration, r.State)
			if err != nil {
				return err
			}
			signable = r
		case *Signature:
			_, err := w.tx.Execv(`
UPDATE openpgp_sig SET
	state = $2, expiration = $3, signer_uuid = $4 WHERE uuid = $1`,
				r.ScopedDigest, r.State, r.Expiration, r.RIssuerFingerprint)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return
}

// UUID_LEN is the size of unique primary keys generated for certain
// database records. The length is chosen to approximate 256 bits of security.
// When Ascii85 encoding is used, log(2**256, 85) = 39.9413926456896
const UUID_LEN = 40

// NewUuid creates a new randomly generated, secure unique identifier.
func NewUuid() (string, error) {
	buf := bytes.NewBuffer([]byte{})
	enc := ascii85.NewEncoder(buf)
	n, err := io.CopyN(enc, rand.Reader, UUID_LEN)
	if err != nil {
		return "", err
	}
	if n < UUID_LEN {
		return "", errors.New("Failed to generate UUID")
	}
	return string(buf.Bytes()), nil
}

// UpdateKeyRelations updates the foreign-key relations between
// matching public key packet records to represent the state of the
// given public key.
func (w *Worker) UpdateKeyRelations(pubkey *Pubkey) (err error) {
	var signable PacketRecord
	err = pubkey.Visit(func(rec PacketRecord) error {
		switch r := rec.(type) {
		case *Pubkey:
			signable = r
		case *Subkey:
			signable = r
		case *UserId:
			return w.updatePrimaryUid(pubkey, r)
			signable = r
		case *UserAttribute:
			return w.updatePrimaryUat(pubkey, r)
			signable = r
		case *Signature:
			switch s := signable.(type) {
			case *Pubkey:
				return w.updatePubkeyRevsig(s, r)
			case *Subkey:
				return w.updateSubkeyRevsig(s, r)
			case *UserId:
				return w.updateUidRevsig(s, r)
			case *UserAttribute:
				return w.updateUatRevsig(s, r)
			}
		}
		return nil
	})
	return
}

func (w *Worker) updatePubkeyRevsig(pubkey *Pubkey, r *Signature) error {
	if pubkey.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_pubkey SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updateSubkeyRevsig(subkey *Subkey, r *Signature) error {
	if subkey.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_subkey SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, subkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updateUidRevsig(uid *UserId, r *Signature) error {
	if uid.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_uid SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, uid.ScopedDigest); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updateUatRevsig(uat *UserAttribute, r *Signature) error {
	if uat.RevSigDigest.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_uat SET revsig_uuid = $1 WHERE uuid = $2`,
			r.ScopedDigest, uat.ScopedDigest); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updatePrimaryUid(pubkey *Pubkey, r *UserId) error {
	if pubkey.PrimaryUid.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_pubkey SET primary_uid = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) updatePrimaryUat(pubkey *Pubkey, r *UserAttribute) error {
	if pubkey.PrimaryUat.String == r.ScopedDigest {
		if _, err := w.tx.Execv(`
UPDATE openpgp_pubkey SET primary_uat = $1 WHERE uuid = $2`,
			r.ScopedDigest, pubkey.RFingerprint); err != nil {
			return err
		}
	}
	return nil
}
