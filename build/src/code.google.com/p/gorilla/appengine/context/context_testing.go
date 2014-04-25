// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !appengine

package context

import (
	"net/http"

	"appengine"
	"gae-go-testing.googlecode.com/git/appenginetesting"
)

var context appengine.Context

// New returns a new testing context.
func New(r *http.Request) appengine.Context {
	if appengine.IsDevAppServer() && r.Header.Get("App-Testing") != "" {
		if context == nil {
			var err error
			if context, err = appenginetesting.NewContext(nil); err != nil {
				panic(err)
			}
		}
		return context
	}
	return appengine.NewContext(r)
}

// Close closes a testing context registered when New() is called.
func Close() {
	if context != nil {
		context.(*appenginetesting.Context).Close()
		context = nil
	}
}
