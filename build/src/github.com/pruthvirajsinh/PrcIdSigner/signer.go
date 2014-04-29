package PrcIdSigner

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/packet"
	"crypto"
	"errors"
)

//SignPubKeyPKS takes asciiarmored private key which will sign the public key
//Public key is also ascii armored,pripwd is password of private key in string
//This function will return ascii armored signed public key i.e. (pubkey+sign by prikey)
//If lifeTime==0 then signature doesnt expire
func SignPubKeyPKS(asciiPub string, asciiPri string, pripwd string, lifeTime uint32) (asciiSignedKey string, err error) {
	//get Private key from armor
	_, priEnt, errPri := GetPri(asciiPri, pripwd) //pripwd is the password todecrypt the private key
	_, pubEnt, errPub := GetPub(asciiPub)         //This will generate signature and add it to pubEnt
	if errPri != nil {
		err = errPri
		return
	}
	if errPub != nil {
		err = errPub
		return
	}
	usrIdstring := ""
	for _, uIds := range pubEnt.Identities {
		usrIdstring = uIds.Name

	}
	var prcPubEnt, prcPriEnt PrcEntity
	prcPubEnt.Entity = &pubEnt
	prcPriEnt.Entity = &priEnt
	//prcPubEnt
	//fmt.Println(usrIdstring)
	myConf := &packet.Config{DefaultHash: crypto.SHA1}
	errSign := prcPubEnt.PRCSignIdentityLifeTime(usrIdstring, prcPriEnt, myConf, lifeTime)
	if errSign != nil {
		err = errSign
		return
	}
	idnts := pubEnt.Identities
	for _, sss := range idnts {
		for _ = range sss.Signatures {
			asciiSignedKey, err = PubEntToAsciiArmor(pubEnt)
		}
	}
	return
}

//GetPub gets packet.PublicKey and openpgp.Entity of Public Key from ascii armor
func GetPub(asciiPub string) (pubKey packet.PublicKey, retEntity openpgp.Entity, err error) {
	read1 := bytes.NewReader([]byte(asciiPub))
	entityList, errReadArm := openpgp.ReadArmoredKeyRing(read1)

	if errReadArm != nil {
		err = errReadArm
		return
	}
	for _, pubKeyEntity := range entityList {
		if pubKeyEntity.PrimaryKey != nil {
			pubKey = *pubKeyEntity.PrimaryKey
			retEntity = *pubKeyEntity
		}
	}
	return
}

//GetPri gets packet.PrivateKEy and openpgp.Entity of Decrypted Private Key from ascii armor
func GetPri(asciiPri string, pripwd string) (priKey packet.PrivateKey, priEnt openpgp.Entity, err error) {
	read1 := bytes.NewReader([]byte(asciiPri))
	entityList, errReadArm := openpgp.ReadArmoredKeyRing(read1)
	if errReadArm != nil {
		//		fmt.Println("Reading PriKey ", errReadArm.Error())
		err = errReadArm
		return
	}
	for _, can_pri := range entityList {
		smPr := can_pri.PrivateKey
		retEntity := can_pri
		if smPr == nil {
			//			fmt.Println("No Private Key")
			err = errors.New("No private key found in armor")
			return
		}

		priKey = *smPr

		errDecr := priKey.Decrypt([]byte(pripwd))
		if errDecr != nil {
			//			fmt.Println("Decrypting ", errDecr.Error())
			err = errDecr
			return
		}
		retEntity.PrivateKey = &priKey
		priEnt = *retEntity
	}

	return
}

//PubEntToAsciiArmor creates ASscii Armor from pubEnt of type openpgp.Entity
func PubEntToAsciiArmor(pubEnt openpgp.Entity) (asciiEntity string, err error) {
	gotWriter := bytes.NewBuffer(nil)
	wr, errEncode := armor.Encode(gotWriter, openpgp.PublicKeyType, nil)
	if errEncode != nil {
		//		fmt.Println("Encoding Armor ", errEncode.Error())
		err = errEncode
		return
	}
	errSerial := pubEnt.Serialize(wr)
	if errSerial != nil {
		//		fmt.Println("Serializing PubKey ", errSerial.Error())
	}
	errClosing := wr.Close()
	if errClosing != nil {
		//		fmt.Println("Closing writer ", errClosing.Error())
	}
	asciiEntity = gotWriter.String()
	return
}
