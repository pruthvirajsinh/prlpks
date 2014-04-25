// prcDelete
package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	. "github.com/pruthvirajsinh/prlpks/errors"
	"github.com/pruthvirajsinh/prlpks/hkp"
	"log"
	"strings"
)

type DeleteResult struct {
	// email of the public key
	Email string
	//Message to be displayed at DelResponse Screen
	DeleteMessage string
}

func (w *Worker) HandleDeleteReq(delReq *hkp.DeleteReq) {
	var allResults []*DeleteResult
	delres := new(DeleteResult)

	resKeys, err := w.LookupKeys(delReq.EmailToDelete, 2)
	if err == ErrKeyNotFound || len(resKeys) <= 0 { //No key found by Email
		fmt.Println("Not found by email,Search by Id = ", delReq.EmailToDelete)
		foundKey, err1 := w.LookupKey(delReq.EmailToDelete) //Find by ID
		if err1 == nil && foundKey != nil {
			resKeys = append(resKeys, foundKey)
		} else {
			err = err1
		}
		//fmt.Println(err)
	}

	//Handling OTL verified when multiple keys with same email is to be deleted.
	//OTL handeler will set delreq.KeyID to get unique key
	if delReq.KeyID != "" {
		fmt.Println("Search by delReq.KeyID = ", delReq.KeyID)
		foundKey, err1 := w.LookupKey(delReq.KeyID) //Find by ID
		if err1 == nil && foundKey != nil {
			resKeys = nil
			resKeys = append(resKeys, foundKey)
		}
		err = err1
		//fmt.Println(err)
	}

	if err == ErrKeyNotFound || len(resKeys) <= 0 { //No key found

		delres.DeleteMessage = "No such key found on the server."
		delres.Email = ""
	} else if err == ErrTooManyResponses || len(resKeys) > 1 {
		delres.DeleteMessage = "Please type full e-mail and try again"
		delres.Email = ""

	} else if err != nil {
		delres.DeleteMessage = err.Error()
	} else { //Key Found,Formulate veri_data

		uIds := resKeys[0].UserIds()
		if len(uIds) > 0 {
			delres.Email = uIds[0].UserId.Email
		}
		//delres.DeleteMessage = fmt.Sprintf("Key Found For E-mail %s \nA verification link has been sent to above E-mail address.The link will expire in %d day/s. Please Check your email.",
		//	delres.Email, ExpInDays)

		//First Check weather we are the authority for it
		ownAuth, err1 := GetOwnAuthority()
		if err1 != nil {
			delres.Email = delres.Email
			delres.DeleteMessage = "Couldnt Get Own Authority"
			allResults = append(allResults, delres)
			delReq.Response() <- &DeleteResponse{DeleteResults: allResults}
			return
		}
		underAuth := false
		email1 := delres.Email
		splits := strings.Split(email1, "@")
		domain := splits[len(splits)-1]
		msg := "Sorry. You can Delete keys of the following domains only : "
		for _, dom := range ownAuth.DomainsUnderAuth {
			msg += dom + " "
			if dom == domain {
				underAuth = true
				break
			}
		}

		if underAuth == false { //Check by explicit Auths
			err = GetExplicitAuths(email1)
			if err != nil {
				underAuth = true
			}
		}

		if underAuth == false {
			delres.Email = delReq.EmailToDelete
			delres.DeleteMessage = msg
			allResults = append(allResults, delres)
			delReq.Response() <- &DeleteResponse{DeleteResults: allResults}
			return
		}
		//Checked weather its under our own authority

		pubKeyToDelete := resKeys[0]
		isVerified, otlState := w.Verify(delres.Email, "", *pubKeyToDelete, int16(2))
		fmt.Println("prc_delete.go:Is Request Verified??: ", isVerified)

		if isVerified {

			if _, err = w.Begin(); err != nil {
				log.Println("Delete", err)
				delres.Email = delres.Email
				delres.DeleteMessage = "Unfortunately we couldn't delete the requested key.Please try again later with new request."
				allResults = append(allResults, delres)
				delReq.Response() <- &DeleteResponse{DeleteResults: allResults}
				return
			}
			change, err1 := w.deleteKey(pubKeyToDelete)
			if err = w.Commit(); err != nil {
				log.Println("Delete", err)
				delres.Email = delres.Email
				delres.DeleteMessage = "Unfortunately we couldn't delete the requested key.Please try again later with new request."
				allResults = append(allResults, delres)
				delReq.Response() <- &DeleteResponse{DeleteResults: allResults}
				return
			}

			if err1 != nil {
				delres.DeleteMessage = "Unfortunately we couldn't delete the requested key.Please try again later with new request."
			} else {
				delres.DeleteMessage = "Successfully Deleted key."
				w.notifyChange(&change)
			}

		} else {

			if otlState == OTLNewOtlMade {
				delres.DeleteMessage = fmt.Sprintf("Key Found For E-mail %s \nA verification link has been sent to above E-mail address.The link will expire in %d day/s. Please Check your email.", delres.Email, ExpInDays)
				//fmt.Println("OTL NOT FOUND!!")

			} else if otlState == OTLExpired {
				delres.DeleteMessage = fmt.Sprintf("The link you have clicked has expired. Please submit your key again.")
				//fmt.Println("OTL Expired!!")

			} else if otlState == OTLNotVerified {
				delres.DeleteMessage = fmt.Sprintf("A request for same key has already been made.Please Check your email %s", delres.Email)
				//fmt.Println("OTL Not Verified!!")
			} else if otlState == ErrorSendingMail {
				delres.DeleteMessage = fmt.Sprintf("Unfortunately we were unable to send an e-mail to %s Please try after sometime with new request", delres)
			}
		}

	}
	allResults = append(allResults, delres)
	delReq.Response() <- &DeleteResponse{DeleteResults: allResults}
	//a.Response() <- &AddResponse{Changes: changes, Errors: readErrors}
	return
}

func (w *Worker) deleteKey(pubKeyToDelete *Pubkey) (keyChange KeyChange, err error) {
	//fmt.Println("In DB Delete,for =", pubKeyToDelete.KeyId())

	//tx := w.db.MustBegin()
	w.tx.Execl(`DELETE FROM openpgp_pubkey WHERE uuid = $1`, pubKeyToDelete.Uuid())
	//err = tx.Commit()

	if err == nil {
		//Rememeber while calling that caller has to HandleKeyUpdate
		//so that it will delete node from ptree
		keyChange.Type = KeyDeleted
		keyChange.CurrentMd5 = pubKeyToDelete.Md5
		log.Println("MD5:", keyChange.CurrentMd5)
		//w.notifyChange(&keyChange)
	} else {
		fmt.Println("Error while DB delete err: ", err)
	}

	return
}

func (w *Worker) reconDeleteKey(rk *LocalDeleteKey) hkp.Response {
	//resp := &ReconDeleteResponse{}
	// Attempt to parse and delete key
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
	//fmt.Println("In reconDelete calling w.DeleteKey for Key Id =  ", pubkeys[0].KeyId())
	email, _ := GetEmailFromPubKey(*pubkeys[0])

	//fmt.Println("reconDeleteKey", rk.verifiedDomains)

	if !IsAuhtorized(email, rk.verifiedDomains) {
		fmt.Print("_")
		return &ErrorResponse{errors.New(fmt.Sprint(email, " Not Verified.Can't delete."))}
	}

	if _, err = w.Begin(); err != nil {
		log.Println("reconDelete", err)
		return &ErrorResponse{err}
	}
	change, err1 := w.deleteKey(pubkeys[0])
	if err = w.Commit(); err != nil {
		log.Println("reconDelete", err)
		return &ErrorResponse{err}
	}

	if err1 != nil {
		log.Println("reconDelete", err1)
		return &ErrorResponse{err1}
	}
	w.notifyChange(&change)
	resp := &ReconDeleteResponse{Change: &change, Err: nil}
	return resp
}
