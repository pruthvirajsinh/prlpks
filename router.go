/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package prlpks

import (
	"flag"
	"go/build"
	"net/http"
	"os"
	"path/filepath"

	"code.google.com/p/gorilla/mux"
)

// System installed location for static files.
const INSTALL_WEBROOT = "/var/lib/prlpks/www"

// prlpks package, used to locate static files when running from source.
const PRLPKS_PKG = "github.com/pruthvirajsinh/prlpks" // Any way to introspect?

// Response for HTTP 500.
const APPLICATION_ERROR = "APPLICATION ERROR"

// Response for HTTP 400.
const BAD_REQUEST = "BAD REQUEST"

// Path to prlpks's installed www directory
func init() {
	flag.String("webroot", "",
		"Location of static web server files and templates")
}
func (s *Settings) Webroot() string {
	webroot := s.GetString("webroot")
	if webroot != "" {
		return webroot
	}
	if fi, err := os.Stat(INSTALL_WEBROOT); err == nil && fi.IsDir() {
		webroot = INSTALL_WEBROOT
	} else if p, err := build.Default.Import(PRLPKS_PKG, "", build.FindOnly); err == nil {
		try_webroot := filepath.Join(p.Dir, "instroot", INSTALL_WEBROOT)
		if fi, err := os.Stat(try_webroot); err == nil && fi.IsDir() {
			webroot = try_webroot
		}
	}
	s.Set("webroot", webroot)
	return webroot
}

// StaticRouter configures HTTP request handlers for static media files.
type StaticRouter struct {
	*mux.Router
}

// NewStaticRouter constructs a new static media router and sets up all request handlers.
func NewStaticRouter(r *mux.Router) *StaticRouter {
	sr := &StaticRouter{Router: r}
	sr.HandleAll()
	return sr
}

// HandleAll sets up all request handlers for prlpks static media.
func (sr *StaticRouter) HandleAll() {
	sr.HandleMainPage()
	sr.HandleFonts()
	sr.HandleCss()
}

// HandleMainPage handles the "/" top-level request.
func (sr *StaticRouter) HandleMainPage() {
	sr.HandleFunc("/",
		func(resp http.ResponseWriter, req *http.Request) {
			http.Redirect(resp, req, "/openpgp/lookup", http.StatusMovedPermanently)
		})
}

// HandleFonts handles all embedded web font requests.
func (sr *StaticRouter) HandleFonts() {
	sr.HandleFunc(`/fonts/{filename:.*\.ttf}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(Config().Webroot(), "fonts", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
}

// HandleCSS handles all embedded cascading style sheet (CSS) requests.
func (sr *StaticRouter) HandleCss() {
	sr.HandleFunc(`/css/{filename:.*\.css}`,
		func(resp http.ResponseWriter, req *http.Request) {
			filename := mux.Vars(req)["filename"]
			path := filepath.Join(Config().Webroot(), "css", filename)
			if stat, err := os.Stat(path); err != nil || stat.IsDir() {
				http.NotFound(resp, req)
				return
			}
			http.ServeFile(resp, req, path)
		})
}
