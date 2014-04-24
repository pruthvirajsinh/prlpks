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
	"bytes"
	"crypto/md5"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pruthvirajsinh/symflux/recon"
	"github.com/stretchr/testify/assert"

	"github.com/pruthvirajsinh/prlpks/hkp"
)

func TestHashqueryResponse(t *testing.T) {
	key := MustInputAscKey(t, "uat.asc")
	resp := HashQueryResponse{[]*Pubkey{key}}
	rec := httptest.NewRecorder()
	err := resp.WriteTo(rec)
	assert.Nil(t, err)
	assert.Equal(t, 200, rec.Code)
}

func TestHashqueryRequest(t *testing.T) {
	key := MustInputAscKey(t, "uat.asc")
	// Determine reference digest to compare with
	h := md5.New()
	refDigestStr := SksDigest(key, h)
	refDigest := h.Sum(nil)
	// Parse url for request
	url, err := url.Parse("/pks/hashquery")
	assert.Nil(t, err)
	// hashquery contents (sks recon wire protocol)
	var buf bytes.Buffer
	err = recon.WriteInt(&buf, 1)
	assert.Nil(t, err)
	err = recon.WriteInt(&buf, len(refDigest))
	assert.Nil(t, err)
	_, err = buf.Write(refDigest)
	assert.Nil(t, err)
	// Create an HTTP request
	req := &http.Request{
		Method: "POST",
		URL:    url,
		Body:   ioutil.NopCloser(bytes.NewBuffer(buf.Bytes())),
	}
	// Parse it
	hq := hkp.NewHashQuery()
	hq.Request = req
	err = hq.Parse()
	assert.Nil(t, err)
	assert.Equal(t, refDigestStr, hq.Digests[0])
	t.Log(hq.Digests)
}
