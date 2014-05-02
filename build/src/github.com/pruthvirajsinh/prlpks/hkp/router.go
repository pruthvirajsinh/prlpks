/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package hkp

import (
	"log"
	"net/http"

	"code.google.com/p/gorilla/mux"

	"github.com/pruthvirajsinh/prlpks"
	Errors "github.com/pruthvirajsinh/prlpks/errors"
)

func (s *Settings) HttpBind() string {
	return s.GetStringDefault("prlpks.hkp.bind", ":11371")
}

type Service struct {
	Requests RequestChan
}

func NewService() *Service {
	return &Service{make(RequestChan)}
}

type Router struct {
	*mux.Router
	*Service
}

func NewRouter(r *mux.Router) *Router {
	hkpr := &Router{Router: r, Service: NewService()}
	hkpr.HandleAll()
	return hkpr
}

func (r *Router) HandleAll() {
	r.HandleWebUI()
	r.HandlePksLookup()
	r.HandlePksAdd()
	r.HandlePksHashQuery()
	//PRC START
	r.HandleOTLVerify()
	r.HandleDeleteRequest()
	r.HandleGetAllStates()
	//PRC END
}

func (r *Router) Respond(w http.ResponseWriter, req Request) {
	err := req.Parse()
	if err != nil {
		log.Println("Error parsing request:", err)
		http.Error(w, prlpks.APPLICATION_ERROR+"\n"+err.Error(), 400)
		return
	}
	r.Requests <- req
	resp := <-req.Response()
	if resp.Error() != nil {
		log.Println("Error in response:", resp.Error())
	}
	err = resp.WriteTo(w)
	if err != nil {
		log.Println(resp, err)
		// Try to respond with an error
		http.Error(w, prlpks.APPLICATION_ERROR+"\n"+err.Error(), 500)
	}
}

func (r *Router) HandlePksLookup() {
	r.HandleFunc("/pks/lookup",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &Lookup{Request: req})
		})
}

func (r *Router) HandlePksAdd() {
	r.HandleFunc("/pks/add",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &Add{Request: req})
		})
}

func (r *Router) HandlePksHashQuery() {
	r.HandleFunc("/pks/hashquery",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &HashQuery{Request: req})
		})
}

func (r *Router) HandleWebUI() {
	r.HandleFunc("/openpgp/add",
		func(w http.ResponseWriter, req *http.Request) {
			var err error
			if SearchFormTemplate == nil {
				err = Errors.ErrTemplatePathNotFound
			} else {
				err = AddFormTemplate.ExecuteTemplate(w, "layout", nil)
			}
			if err != nil {
				http.Error(w, prlpks.APPLICATION_ERROR, 500)
			}
		})
	r.HandleFunc("/openpgp/lookup",
		func(w http.ResponseWriter, req *http.Request) {
			var err error
			if SearchFormTemplate == nil {
				err = Errors.ErrTemplatePathNotFound
			} else {
				err = SearchFormTemplate.ExecuteTemplate(w, "layout", nil)
			}
			if err != nil {
				http.Error(w, prlpks.APPLICATION_ERROR, 500)
			}
		})
	r.HandleFunc("/prc/requests/delete",
		func(w http.ResponseWriter, req *http.Request) {
			var err error
			if DeleteFormTemplate == nil {
				err = Errors.ErrTemplatePathNotFound
			} else {
				err = DeleteFormTemplate.ExecuteTemplate(w, "layout", nil)
			}
			if err != nil {
				http.Error(w, prlpks.APPLICATION_ERROR, 500)
			}
		})

}

//PRC EDIT START
func (r *Router) HandleOTLVerify() {
	r.HandleFunc("/prc/verify",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &OTLVerify{Request: req})
		})
}

//TO DELETE
func (r *Router) HandleDeleteRequest() {
	r.HandleFunc("/prc/delete",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &DeleteReq{Request: req})
		})
}

//TO Get AllStates
func (r *Router) HandleGetAllStates() {
	r.HandleFunc("/prc/getAllStates",
		func(w http.ResponseWriter, req *http.Request) {
			r.Respond(w, &AllStatesReq{Request: req})
		})
}

//PRC END
