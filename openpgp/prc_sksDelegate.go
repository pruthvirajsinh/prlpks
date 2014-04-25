// prc_sksDelegate
package openpgp

import (
	//	"errors"
	"bytes"
	"code.google.com/p/go.crypto/openpgp/armor"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

//TODO:
//1.Create a HKP Get query to SKS using Get URL
//1.1 Search : http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=sam+john
//1.2.Hash ID: http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=0x4F15D7AB
//2.Get Keys from it.Append them.
//3.Set a flag to display warning

//const sksPrefix = `http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=`

func DelegateToSKS(searchquery string, toServer string) (keys []*Pubkey, err error) {

	resp, errG := http.Get(fmt.Sprintf("http://" + toServer + "/pks/lookup?op=get&search=" + searchquery))
	if errG != nil {
		err = errG
		return
	}

	if resp.StatusCode == http.StatusNotFound {
		return
	}
	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	{

		defer resp.Body.Close()
		bodyBuf, errR := ioutil.ReadAll(resp.Body)
		if errR != nil {
			return
		}
		body = bytes.NewBuffer(bodyBuf)
	}

	// Check and decode the armor
	armorBlock, errD := armor.Decode(body)
	if errD != nil {
		err = errD
		fmt.Println("armor.decode", err)
		return
	}

	for readKey := range ReadKeys(armorBlock.Body) {
		if readKey.Error != nil {
			fmt.Println("ReadKeys", readKey.Error)
		} else {
			log.Println("delegate.go: Found a key from request!! = ", readKey.Pubkey.KeyId())
			//fmt.Println("delegate.go: Found a key from request!! = ", readKey.Pubkey.KeyId())
			keys = append(keys, readKey.Pubkey)
		}
	}

	return
}
