// prc_pks_signer

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
