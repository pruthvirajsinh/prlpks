// prc_CurrState
package openpgp

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pruthvirajsinh/PrcIdSigner"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"
)

//PRC Start

type AuthorizedState struct {
	TimeStamp       int64
	FromAuthority   Authority
	ToPeer          string //HkpAddr of direct peer of authority
	AsciiSigOfState string
}

func (ast *AuthorizedState) GetStateString() (stateString string, err error) {

	stateString += strconv.FormatInt(ast.TimeStamp, 10)
	if stateString == "" {
		err = errors.New("No TimeStamp")
		return
	}
	authStr, err1 := ast.FromAuthority.GetString()
	if err1 != nil {
		err = err1
		return
	}
	stateString += authStr
	if ast.ToPeer == "" {
		err = errors.New("No ToPeer")
		return
	}

	stateString += ast.ToPeer
	/*
		if strconv.FormatInt(ast.TotalNumOfKeys, 10) == "" {
			err = errors.New("No Total Keys")
			return
		}
		stateString += strconv.FormatInt(ast.TotalNumOfKeys, 10)
		if strconv.FormatInt(ast.NumOfAuthKeys, 10) == "" {
			err = errors.New("No No of Auth Keys")
			return
		}
		stateString += strconv.FormatInt(ast.NumOfAuthKeys, 10)
	*/
	return
}

func (ast *AuthorizedState) SignState(asciiPriKey string, pripwd string) (err error) {

	stateString, err1 := ast.GetStateString()

	if err1 != nil {
		err = err1
		return
	}
	//fmt.Println("StateString :", stateString)

	var opBuf bytes.Buffer
	var ipBuf bytes.Buffer
	ipBuf.WriteString(stateString)

	//func ArmoredDetachSignText(w io.Writer, signer *Entity,
	//message io.Reader, config *packet.Config) error
	_, priEnt, errGetPri := PrcIdSigner.GetPri(asciiPriKey, pripwd)
	if errGetPri != nil {
		err = errGetPri
		return
	}
	err = openpgp.ArmoredDetachSign(&opBuf, &priEnt, &ipBuf, nil)
	if err == nil {
		//fmt.Println("Detached Signature = ", string(opBuf.Bytes()))
		ast.AsciiSigOfState = string(opBuf.Bytes())
	} else {
		fmt.Println("Error While Signing State", err.Error())
	}
	return
	//fmt.Println("Current State", ast)
}

//const ErrStateBadSign = errors.New("Sign Doesnt Match")

func (ast *AuthorizedState) VerifyState(asciiPubKey string) (err error) {
	var stateString string
	stateString, err = ast.GetStateString()
	if err != nil {
		return
	}
	//fmt.Println("verify:StateString :", stateString)
	var sigBuf bytes.Buffer
	sigBuf.WriteString(ast.AsciiSigOfState)
	var stateStrBuf bytes.Buffer
	stateStrBuf.WriteString(stateString)

	//func CheckArmoredDetachedSignature(keyring KeyRing, signed, signature io.Reader)
	// (signer *Entity, err error)
	//KeyRing is an interface:=>EntityList implements KeyRing hence pass Entity List
	_, pubEnt, errGetPub := PrcIdSigner.GetPub(asciiPubKey)
	if errGetPub != nil {
		err = errGetPub
		return
	}
	pubEntList := &openpgp.EntityList{&pubEnt}
	//var signer *openpgp.Entity
	_, err = openpgp.CheckArmoredDetachedSignature(pubEntList, &stateStrBuf, &sigBuf)

	if err == nil {
		//fmt.Println("Verify:Signer Id = ", signer.Identities)
	} else {
		fmt.Println(err.Error())
	}
	return
}

func GetAuthsForDomFromStates(remoteStatesInJSON string) (authsForDomains []AuthForDomain, err error) {
	//1.GetAuths from Remote States
	//2.Get Domains
	//3.Verify Auths from dns TXT records for domain
	//4.If verified add to authorities
	allStates, err1 := GetStatesFromJSON(remoteStatesInJSON)
	if err1 != nil {
		err = err1
		return
	}
	for _, state := range allStates {
		claimedAuth := state.FromAuthority
		for _, domain := range claimedAuth.DomainsUnderAuth {
			pksTxtAuth, err2 := GetPksAuthTXTRecord(domain)
			if err2 != nil {
				log.Println(err2)
				continue
			}

			pubKey, _, err3 := PrcIdSigner.GetPub(claimedAuth.AsciiPubKeyOfAuth)
			if err3 != nil {
				log.Println(err3)
				continue
			}
			pubFP := fmt.Sprintf("%X", pubKey.Fingerprint[:])
			pubFP = strings.ToUpper(pubFP)
			txtFP := strings.ToUpper(pksTxtAuth.keyFingerPrint)
			if txtFP != pubFP {
				fmt.Println(txtFP + " != " + pubFP)
				log.Println("Key FingerPrint differ in DNS Text Record of " + domain)
				continue
			}
			err = state.VerifyState(claimedAuth.AsciiPubKeyOfAuth)
			if err != nil {
				log.Println(err)
				continue
			}
			authsForDomains = append(authsForDomains, AuthForDomain{domain: domain, authority: claimedAuth})
		}
	}
	return
}

func GetOwnCurrentState(toPeer string) (currState AuthorizedState, err error) {

	authOwn, err1 := GetOwnAuthority()
	if err1 != nil {
		err = err1
		return
	}

	currState = AuthorizedState{
		TimeStamp:       time.Now().Unix(),
		FromAuthority:   authOwn,
		ToPeer:          toPeer, //HkpAddr of direct peer of authority
		AsciiSigOfState: ""}

	//Get private Key from config
	str, err1 := GetFileContentsFromConfig("authority.priKeyPath")
	if err1 != nil {
		err = err1
		return
	} else {
		pripwd := Config().GetString("authority.priPwd")
		if pripwd == "" {
			err = errors.New("Private Key Password is not set in config")
			return
		} else {
			err = currState.SignState(str, pripwd)
			if err != nil {
				return
			}
		}
	}

	return
}

func GetFileContentsFromConfig(key string) (contents string, err error) {
	filePath := Config().GetString(key)
	if filePath == "" {
		err = errors.New("Attribute " + key + " is not set in config")
		return
	} else {
		fileBytes, err1 := ioutil.ReadFile(filePath)
		if err1 != nil {
			err = err1
			return
		}
		contents = string(fileBytes)
	}
	return
}

func WriteToFileFromConfig(key string, contents string) (err error) {
	filePath := Config().GetString(key)
	if filePath == "" {
		err = errors.New("Attribute " + key + " is not set in config")
		return
	} else {
		err = ioutil.WriteFile(filePath, []byte(contents), 0666)
		if err != nil {
			return
		}

	}
	return
}

func GetStatesFromJSON(ipjson string) (authStates []AuthorizedState, err error) {
	var states []AuthorizedState
	err = json.Unmarshal([]byte(ipjson), &states)
	if err != nil {
		return
	}
	authStates = states
	return
}

func WriteStatesToJSON(authStates []AuthorizedState) (opJSON string, err error) {

	var msg []AuthorizedState
	msg = authStates
	var jsonStr []byte
	jsonStr, err = json.Marshal(msg)
	if err != nil {
		return
	}
	opJSON = string(jsonStr)
	return
}

func GetStateForDomain(allStates []AuthorizedState, domain string) (stateForDomain AuthorizedState, err error) {
	found := false
	for _, state := range allStates {
		for _, dom := range state.FromAuthority.DomainsUnderAuth {
			if dom == domain {
				if state.TimeStamp > stateForDomain.TimeStamp {
					stateForDomain = state
					found = true
				}
			}
		}
	}
	if found == false {
		err = errors.New(fmt.Sprint("Could Not Find a State For Domain ", domain))
	}
	return
}

func PrintState(state AuthorizedState) (msg string) {
	msg = state.FromAuthority.HkpAddr + "->" + state.ToPeer + " : " + strconv.FormatInt(state.TimeStamp, 10)
	return
}
