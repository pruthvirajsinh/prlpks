// prc_authority
package openpgp

import (
	"encoding/json"
	"errors"
	//	"io"
	//	"io/ioutil"
	//	"os"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	//	"time"
)

type Authority struct {
	HkpAddr           string   //Address in string format of the machine of authority
	DomainsUnderAuth  []string //Domains which are under this authority
	EmailOfAuthority  string   //e.g. admin@authorize.com
	AsciiPubKeyOfAuth string   //Ascii Armored Public Key of Auhtority
	//NOTE:Most probably the peer itself will be authority for keys directly uploaded to it.
}

func (auth Authority) GetString() (stringOfAuth string, err error) {
	if auth.HkpAddr != "" {
		stringOfAuth += auth.HkpAddr

		for _, dsua := range auth.DomainsUnderAuth {
			stringOfAuth += dsua
		}
		if auth.EmailOfAuthority == "" || auth.AsciiPubKeyOfAuth == "" {
			err = errors.New("Authority doesnt contain Email or Public Key")
		}
		stringOfAuth += auth.EmailOfAuthority + auth.AsciiPubKeyOfAuth
	} else {
		err = errors.New("Authority doesnt contain HKP Address")
		return
	}
	return
}

type AuthForDomain struct {
	domain    string
	authority Authority
}

func GetAuthForAllDomains(remoteStatesInJSON string) (authsForDomains []AuthForDomain, err error) {

	authOwn, _ := GetOwnAuthority()

	for _, domn := range authOwn.DomainsUnderAuth {
		authsForDomains = append(authsForDomains, AuthForDomain{domain: domn, authority: authOwn})
	}

	rmtAuthsForDom, err3 := GetAuthsForDomFromStates(remoteStatesInJSON)
	if err3 != nil {
		err = err3
		return
	}
	for _, authsFrDom := range rmtAuthsForDom {
		authsForDomains = append(authsForDomains, authsFrDom)
	}

	return
}

type ExplicitAuth struct {
	Emails []string //Emails that we are explicitly authorizing ourselves to handle.
}

func GetExplicitAuths(email string) (err error) {
	defer func() {
		if err != nil {
			log.Println(" Explicit Auth Verification for ", email, " failed: ", err)
		}
	}()
	//1.Read JSON
	//2.Get expAuth Struct object
	//3.single and regular Expression
	//4.Verify return err or nil

	str, err1 := GetFileContentsFromConfig("authority.ExplicitAuthFile")
	if err1 != nil {
		err = err1
		return
	}

	var exAuths []ExplicitAuth

	err = json.Unmarshal([]byte(str), &exAuths)
	if err != nil {
		return
	}
	found := false
	for _, excAuth := range exAuths {
		for _, excEmail := range excAuth.Emails {
			//First do simple matching,If no match then do regexp matching.
			if email == excEmail {
				found = true
				break
			}
			//Do regexp matching
			found, err = regexp.MatchString(excEmail, email)
			if found {
				break
			}
		}
	}
	if found {
		return
	} else {
		err = errors.New("Not in our authority")
		return
	}
	return

}

func GetAuthForDomain(domainKey string, remoteStatesInJSON string) (authority Authority, err error) {
	allauths, err1 := GetAuthForAllDomains(remoteStatesInJSON)
	if err1 != nil {
		err = err1
		return
	}
	for _, auth := range allauths {
		if auth.domain == domainKey {
			authority = auth.authority
			return
		}
	}
	err = errors.New("Could Not Find Authority for that domain")
	return
}

func GetAuthForHkpAddr(HkpAddrKey string, remoteStatesInJSON string) (authority Authority, err error) {
	allauths, err1 := GetAuthForAllDomains(remoteStatesInJSON)
	if err1 != nil {
		err = err1
		return
	}
	for _, auth := range allauths {
		if auth.authority.HkpAddr == HkpAddrKey {
			authority = auth.authority
			return
		}
	}
	err = errors.New("Could Not Find Authority for that address")
	return
}
func GetAuthForEmail(email string, remoteStatesInJSON string) (auth Authority, err error) {
	splits := strings.Split(email, "@")
	domain := splits[len(splits)-1]
	auth, err = GetAuthForDomain(domain, remoteStatesInJSON)
	return
}

func GetOwnAuthority() (auth Authority, err error) {
	ownAddr := Config().GetString("authority.ownAddr")
	if ownAddr == "" {
		err = errors.New("No OwnAddress Set in Config File")
		return
	}
	domns := Config().GetStrings("authority.domainsUnderAuth")

	if len(domns) < 1 {
		err = errors.New("No doamins under own Found")
	}

	eml := Config().GetString("authority.email")
	if eml == "" {
		err = errors.New("No Email Set for own authority")
	}
	pubKey, err1 := GetFileContentsFromConfig("authority.pubKeyPath")
	if err1 != nil {
		err = err1
		return
	}
	auth = Authority{
		HkpAddr:           ownAddr, //Address in string format of the machine of authority
		DomainsUnderAuth:  domns,   //Domains which are under this authority
		EmailOfAuthority:  eml,     //e.g. admin@authorize.com
		AsciiPubKeyOfAuth: pubKey}
	return
}

func IsUnderAuth(publicKey Pubkey) (err error) {

	email, err1 := GetEmailFromPubKey(publicKey)
	if err1 != nil {
		err = err1
		return
	}

	ownAuth, err1 := GetOwnAuthority()
	if err1 != nil {
		//		fmt.Println(err1)
		err = err1
		return
	}

	underAuth := false
	splits := strings.Split(email, "@")
	domain := splits[len(splits)-1]

	msg := "Sorry. This server can upload/delete keys of the following domains only : "
	for _, dom := range ownAuth.DomainsUnderAuth {
		msg += dom + " "
		if dom == domain {
			underAuth = true
			break
		}
	}
	if underAuth == false {
		err = GetExplicitAuths(email)
		if err != nil {
			err = errors.New(msg)
		}
		return
	}
	return

}

type PksAuthTXT struct {
	authAddr       string //Web address of key server which has authority over this domain
	keyFingerPrint string //Long Fingerprint of Pub key of authority
	since          int64  //Time in Seconds since 1970
}

func GetPksAuthTXTRecord(domain string) (pksAuth PksAuthTXT, err error) {
	txts, err1 := net.LookupTXT(domain)
	found := false
	if err1 != nil {
		log.Println(err1)
		err = err1
		return
	}
	net.LookupAddr(domain)

	for _, r := range txts {
		log.Println("TXT of " + domain + " : " + r)
		rcds := strings.Split(r, "=")
		if len(rcds) != 2 {
			log.Println("Not Found = in TXT Record of " + domain)
		} else if rcds[0] != "pks" {
			log.Println("pks not found in TXT Record of " + domain)
		} else {
			rcds = strings.Split(rcds[1], " ")
			if len(rcds) != 3 {
				log.Println("Not Enough values in TXT Record of domain " + domain)
			} else {
				pksAuth.authAddr = rcds[0]
				//fmt.Println("pks_Addr=", rcds[0])
				//fmt.Println("key_FingerPrint=", rcds[1])
				pksAuth.keyFingerPrint = rcds[1]
				since, err2 := strconv.Atoi(rcds[2])
				if err2 != nil {
					log.Println(err2)
					err = err2
					return
				}
				pksAuth.since = int64(since)
				found = true
				break
				//fmt.Println("time=", time.Unix(int64(since), 0))
			}

		}
	}
	if found == false {
		err = errors.New("TXT Record of domain " + domain + "doesnt contain valid pksAuth Record")
		return

	}
	return
}
