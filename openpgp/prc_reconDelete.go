// prc_reconDelete
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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pruthvirajsinh/symflux/recon"
	//"github.com/pruthvirajsinh/PrcIdSigner"
	"bytes"
	"github.com/pruthvirajsinh/prlpks/hkp"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

//PRC Start
//Handling "/prc/getAllStates"

type AllStatesResult struct {
	allStates []AuthorizedState
}
type LocalDeleteKey struct {
	Keytext         []byte
	response        hkp.ResponseChan
	verifiedDomains []string
}

func UpdateOwnLocalState() (err error) {
	//PRC Start
	//TODO: If ColdBoot = true then always return timestamp=0
	ownAuth, err1 := GetOwnAuthority()
	if err1 != nil {
		err = err1
		return
	}
	ownSt, err1 := GetOwnCurrentState(ownAuth.HkpAddr)
	if err1 != nil {
		fmt.Println("Error while Getting OwnState for Own ", ownAuth.HkpAddr)
		fmt.Println(err1)
		err = err1
		return
	}

	ownStateSl := []AuthorizedState{ownSt}
	jsonStr, err2 := WriteStatesToJSON(ownStateSl)
	if err2 != nil {
		err = err2
		return
	}
	err1 = SaveToLocalStates(ownSt, jsonStr)
	if err1 != nil {
		fmt.Println(err1)
		fmt.Println("Error while Saving OwnState for Own ", ownAuth.HkpAddr)
		err = err1
		return
	}
	return
	//PRC End
}
func GetAllStatesFromPeer(remoteAddr string) (allStates []AuthorizedState, err error) {
	// Make an prc GetAllAuthStates Request

	resp, errG := http.Get(fmt.Sprintf("http://%s/prc/getAllStates", remoteAddr))
	//	"sks/hashquery"))
	if errG != nil {
		fmt.Println("Error While Getting Response for")
		err = errG
		return
	}
	// Store response in memory. Connection may timeout if we
	// read directly from it while loading.
	var body *bytes.Buffer
	{
		defer resp.Body.Close()
		bodyBuf, err1 := ioutil.ReadAll(resp.Body)
		if err1 != nil {
			err = err1
			return
		}
		body = bytes.NewBuffer(bodyBuf)
	}
	contents := body.Bytes()

	//fmt.Printf("Got All States JSON From %s = %s", remoteAddr, string(contents))

	//JSON Unmarshalling to get array 0f Authorized State
	var states []AuthorizedState
	err = json.Unmarshal(contents, &states)
	if err != nil {
		return
	}
	fmt.Println("Got Remote States From :", remoteAddr)
	for _, st := range states {
		fmt.Println(PrintState(st))
	}

	allStates = states
	return
}

func GetLatestLocalStates() (allStates []AuthorizedState, err error) {
	//TODO: Get Current Latest States of all Authorities that we currently have from last reconciliations
	var str string
	str, err = GetFileContentsFromConfig("authority.stateFile")
	if err != nil {
		return
	}
	var states []AuthorizedState
	err = json.Unmarshal([]byte(str), &states)
	if err != nil {
		return
	}

	//Deduplicate Start
	length := len(states) - 1
	for i := 0; i < length; i++ {
		for j := i + 1; j <= length; j++ {
			if states[i].FromAuthority.HkpAddr == states[j].FromAuthority.HkpAddr && states[i].ToPeer == states[j].ToPeer {
				if states[i].TimeStamp >= states[j].TimeStamp {
					states[j] = states[length]
					states = states[0:length]
				} else {
					states[i] = states[j]
					states[j] = states[length]
					states = states[0:length]
				}
				length--
				j--
			}
		}
	}
	//Deduplicate End
	/*
		fmt.Println("Giving Latest Local States:")
		for _, st := range states {
			fmt.Println(PrintState(st))
		}
	*/
	allStates = states
	return
}

func SaveToLocalStates(state AuthorizedState, remoteStatesInJSON string) (err error) {
	//fmt.Println("Request to save to local states with State ", PrintState(state))
	definedAuth, err1 := GetAuthForHkpAddr(state.FromAuthority.HkpAddr, remoteStatesInJSON)
	if err1 != nil {
		err = err1
		return
	}

	if err = state.VerifyState(definedAuth.AsciiPubKeyOfAuth); err != nil {
		return
	}

	filePath := Config().GetString("authority.stateFile")
	if filePath == "" {
		err = errors.New("os.Open Attribute authority.stateFile is not set in config")
		return
	} else {
		stateFile, err1 := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0666)
		if err1 != nil {
			err = err1
			return
		}
		stateFile.Close()

	}

	beforeStates, errLate := GetLatestLocalStates()
	if errLate != nil {
		err = errLate
		return
	}
	/*TODO: Check weather a authority in our authority.json file exists or not,if allowed only then add

	*/
	_, errLocally := GetAuthForHkpAddr(state.FromAuthority.HkpAddr, remoteStatesInJSON)
	if errLocally != nil {
		err = errLocally
		return
	}
	//fmt.Println("before States:", beforeStates)

	found := false
	for _, sts := range beforeStates {
		if state.FromAuthority.HkpAddr == sts.FromAuthority.HkpAddr && state.ToPeer == sts.ToPeer {
			found = true
			break
		}
	}

	var savedLocalStates []AuthorizedState

	if found == true {
		for _, sts := range beforeStates {
			if state.FromAuthority.HkpAddr == sts.FromAuthority.HkpAddr && state.ToPeer == sts.ToPeer {
				if sts.TimeStamp < state.TimeStamp { //If currently saved timestamp is smaller only then replace
					savedLocalStates = append(savedLocalStates, state)
				} else {
					savedLocalStates = append(savedLocalStates, sts)
				}
			} else {
				savedLocalStates = append(savedLocalStates, sts)
			}
		}
	} else {
		savedLocalStates = append(beforeStates, state)
	}

	var jsonStr []byte

	jsonStr, err = json.Marshal(savedLocalStates)
	if err != nil {
		return
	}
	err = WriteToFileFromConfig("authority.stateFile", string(jsonStr))
	if err != nil {
		fmt.Println("Error while writing to state File ", Config().GetString("authority.stateFile"))
	}
	/*
		fmt.Println("Local States After Adding ", PrintState(state), " : ")
		for _, afSt := range savedLocalStates {
			fmt.Println(PrintState(afSt))

		}
	*/

	return
}

func MergeStatesInToLocal(remoteStates []AuthorizedState, remoteStatesInJSON string) (err error) {
	for _, rs := range remoteStates {
		err = SaveToLocalStates(rs, remoteStatesInJSON)
		if err != nil {
			return
		}
	}
	return
}

func GetAllStatesDirectFromAuth(rcvr *recon.Recover) (allStates []AuthorizedState, err error) {
	remoteAddr, err1 := rcvr.HkpAddr()
	if err1 != nil {
		err = err1
		return
	}
	allStates, err = GetAllStatesFromPeer(remoteAddr)

	return
}

func (w *Worker) HandleAllStatesReq(allStatesReq *hkp.AllStatesReq) {
	//Give the Response as AllStatesResult to channel
	var allStatesRes []*AllStatesResult
	localStates, err := GetLatestLocalStates()
	if err != nil {
		fmt.Println("HandleAllStateReq: Error While Getting AllStates ", err)
		return
	}
	allStatesRes = append(allStatesRes, &AllStatesResult{allStates: localStates})
	allStatesReq.Response() <- &AllStatesResponse{AllStatesResults: allStatesRes}
}

func RecoveryAuthentication(remoteStatesInJSON string) (verifiedDomains []string, err error) {

	if remoteStatesInJSON == "" {
		err = errors.New("No JSON Provided")
		return
	}

	//verifiedDomains := make(map[string][]RecoverKey)

	allAuthsForDomain, err1 := GetAuthForAllDomains(remoteStatesInJSON)
	if err1 != nil {
		err = err1
		return
	}

	for _, auth := range allAuthsForDomain {
		verr := verifyDomainForRecover(auth.domain, remoteStatesInJSON)
		if verr == nil {
			//fmt.Println("Updates for domain ", auth.domain, "is accepted")
			verifiedDomains = append(verifiedDomains, auth.domain)
		} else {
			//fmt.Println("Updates for domain ", auth.domain, "is rejected")
			//err = verr
		}
	}
	return
}

func verifyDomainForRecover(domain string, remoteStatesInJSON string) (err error) {
	if remoteStatesInJSON == "" {
		return errors.New("No remoteStateJSON")
	}
	auth, err1 := GetAuthForDomain(domain, remoteStatesInJSON)
	if err1 != nil {
		err = err1
		fmt.Println(err)
		return
	}

	allRemoteStates, err2 := GetStatesFromJSON(remoteStatesInJSON)
	if err2 != nil {
		err = err2
		fmt.Println(err)
		return
	}
	allLocalStates, err3 := GetLatestLocalStates()
	if err3 != nil {
		err = err3
		fmt.Println(err)
		return
	}

	remoteState, err4 := GetStateForDomain(allRemoteStates, domain)
	if err4 != nil {
		err = err4
		fmt.Println("Recover:Not In RemoteStates Hence Reject")
		return
	}

	err = remoteState.VerifyState(auth.AsciiPubKeyOfAuth)
	if err != nil {
		fmt.Println(err)
		return
	}

	localState, err5 := GetStateForDomain(allLocalStates, domain)
	if err5 != nil {
		err = err5
		fmt.Println("Recover:Not In LocalStates Hence Accept")
		return nil
	}

	err = localState.VerifyState(auth.AsciiPubKeyOfAuth)
	if err != nil {
		fmt.Println(err)
		return
	}
	/*Logic for weather allow the key to be inserted or not
	1.TODO:Check Key for signature by authority
	2.If remoteTime > LocalTime Allow
	*/
	if remoteState.TimeStamp > localState.TimeStamp {
		return nil
	} else {
		return errors.New(fmt.Sprint("Local State is older for domain : ", domain))
	}
	return
}

func IsAuhtorized(email string, verifiedDomains []string) (isVerified bool) {
	splits := strings.Split(email, "@")
	domainOfEmail := splits[len(splits)-1]
	for _, domain := range verifiedDomains {
		if domainOfEmail == domain {
			return true
		}
	}
	return false
}
