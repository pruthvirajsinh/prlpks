// prc_otl_handler
package openpgp

/*
TODO:
1.Lookup otl_hash in verify DB >>if1
	2.if2>> Check weather it has been more than two days

		3. Show add screen with
				extra message (ur email id was detected in following request)
				show armor of the add request

				//ADD Button
					4.Set is_verified = true,veri_time=now
					again sends add request to PKS with armor data
				//CANCEL Button stops
					4.Set is_verified = false,veri_time=now

	5.else2>> Show message saying otl expiration
6.else1>> Show message saying no such otl exists

*/
import (
	"fmt"
	"github.com/pruthvirajsinh/prlpks/hkp"
	"log"
	"time"
)

func (w *Worker) PRCOTLVerify(otlv *hkp.OTLVerify) (result_code int) {
	//fmt.Println("prcotlv:raw otlv=", otlv)
	//fmt.Println("prcotlv otl=", otlv.OTLtext)
	/*

		1.Lookup otl_hash in verify DB >>if1
			2.if2>> Check weather it has been more than two days

				3. Show add screen with
						extra message (ur email id was detected in following request)
						show armor of the add request

						//ADD Button
							4.Set is_verified = true,veri_time=now
							again sends add request to PKS with armor data
						//CANCEL Button stops
							4.Set is_verified = false,veri_time=now

			5.else2>> Show message saying otl expiration
		6.else1>> Show message saying no such otl exists

	*/

	Temp_veri := []Veri_data{}

	veri := new(Veri_data)

	w.db.Select(&Temp_veri, `SELECT * FROM verify_email
		WHERE otl_hash=$1`, otlv.OTLtext)

	if len(Temp_veri) == 0 {
		result_code = OTLNotFound
		veri.Is_verified = false
		//fmt.Println("prc_otl_handler.go:No such OTL NOT FOUND in DB")
		//alr_verifAdd := new(hkp.Add)
		//aResp := new(AddResponse)
		keyCh := new(KeyChange)
		keyCh.ChangeMessage = "We are extremely Sorry but NO such Link Exists on this server"
		keyCh.Type = KeyNotChanged
		var changes []*KeyChange
		changes = append(changes, keyCh)
		otlv.Response() <- &AddResponse{Changes: changes}
	} else {
		*veri = Temp_veri[0]
		if veri.Expi_time.Before(time.Now()) {
			result_code = OTLExpired
			keyCh := new(KeyChange)
			keyCh.ChangeMessage = fmt.Sprintf("The link you have clicked has expired at %s", veri.Expi_time.Format(time.RFC850))
			keyCh.Type = KeyNotChanged
			var changes []*KeyChange
			changes = append(changes, keyCh)
			otlv.Response() <- &AddResponse{Changes: changes}
		} else if veri.Is_verified != true {
			//OTL has been found and it has not yet expired or verified
			result_code = OTLNotVerified
			//set isverified =true,verification time=now
			veri.Is_verified = true
			veri.Veri_time = time.Now()

			//Change isverified into DB

			if _, err := w.Begin(); err != nil {
				log.Println("OTL Verifier:Begining...", err)
				keyCh := new(KeyChange)
				keyCh.ChangeMessage = fmt.Sprintf("Problem at server.DB cant begin")
				keyCh.Type = KeyNotChanged
				var changes []*KeyChange
				changes = append(changes, keyCh)
				otlv.Response() <- &AddResponse{Changes: changes}
				return
			}
			w.tx.Execl(`UPDATE verify_email SET veri_time = $1,is_verified= $2
				WHERE otl_hash = $3`, veri.Veri_time, veri.Is_verified, veri.Otl_hash)
			if err := w.Commit(); err != nil {
				log.Println("OTL Verifier:Commiting...", err)
				keyCh := new(KeyChange)
				keyCh.ChangeMessage = fmt.Sprintf("Problem at server.DB cant commit")
				keyCh.Type = KeyNotChanged
				var changes []*KeyChange
				changes = append(changes, keyCh)
				otlv.Response() <- &AddResponse{Changes: changes}
				return
			}

			result_code = OTLVerified
			if veri.Operation == int16(1) {
				verifiedAdd := new(hkp.Add)
				verifiedAdd.Keytext = veri.Key_text
				verifiedAdd.Request = otlv.Request
				verifiedAdd.ShaOfTarget = veri.Hash_pubkey
				verifiedAdd.SetResponse(otlv.Response())
				w.Add(verifiedAdd)
			} else if veri.Operation == int16(2) {
				verifiedDelete := new(hkp.DeleteReq)
				verifiedDelete.EmailToDelete = veri.Pubkey_id
				verifiedDelete.KeyID = veri.Pubkey_id
				verifiedDelete.SetResponse(otlv.Response())
				verifiedDelete.Request = otlv.Request
				w.HandleDeleteReq(verifiedDelete)
			}
		} else if veri.Is_verified { //OTL is already verified
			//fmt.Println("prc_otl_handler.go: OTL is already verified")
			result_code = OTLAlereadyVerified
			//alr_verifAdd := new(hkp.Add)
			//			aResp := new(AddResponse)

			keyCh := new(KeyChange)
			keyCh.ChangeMessage = "The link you have clicked is already used once"
			keyCh.Type = KeyNotChanged
			var changes []*KeyChange
			changes = append(changes, keyCh)
			otlv.Response() <- &AddResponse{Changes: changes}
		}

	}

	/* TO Delete a key
	deleteString := otlv.OTLtext
	//tx := w.db.MustBegin()
	tx.Execl(`DELETE FROM openpgp_pubkey
				WHERE uuid = $1`, deleteString)
	//tx.Commit()
	//DELETE FROM table_name
	//WHERE some_column = some_value
	*/
	return

}

/*
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
*/
