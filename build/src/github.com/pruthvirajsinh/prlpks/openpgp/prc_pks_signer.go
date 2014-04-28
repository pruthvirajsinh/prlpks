// prc_pks_signer
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
	"errors"
	"github.com/pruthvirajsinh/PrcIdSigner"
	//"time"
)

func SignKeyAfterVerification(pubkeyArmor string) (signedKey string, err error) {

	priKeystr, err1 := GetFileContentsFromConfig("authority.priKeyPath")
	if err1 != nil {
		err = err1
		return
	} else {
		pripwd := Config().GetString("authority.priPwd")
		if pripwd == "" {
			err = errors.New("Private Key Password is not set in config")
			return
		} else {
			lifeTime := Config().GetIntDefault("authority.sigLifeTime", 0)
			lifeTime = lifeTime * 24 * 60 * 60
			signedKey, err = PrcIdSigner.SignPubKeyPKS(pubkeyArmor, priKeystr, pripwd, uint32(lifeTime))
			if err != nil {
				return
			}
		}

	}
	return
}
