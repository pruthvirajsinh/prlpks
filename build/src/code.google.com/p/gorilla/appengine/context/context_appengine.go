// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build appengine

package context

import (
	"appengine"
)

// New returns a new appengine.Context.
var New = appengine.NewContext
