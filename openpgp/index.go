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
	"fmt"
	ht "html/template"
	"net/http"
	"strings"
	tt "text/template"
	"time"

	"code.google.com/p/go.crypto/openpgp/packet"

	"github.com/pruthvirajsinh/prlpks/hkp"
)

const indexPageTmplSrc = `{{/*

*/}}{{ define "PageHeader" }}{{/*
*/}}<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd" >
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Search results for '{{ .Lookup.Search }}'</title>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
<style type="text/css">
/*<![CDATA[*/
 .uid { color: green; text-decoration: underline; }
 .warn { color: red; font-weight: bold; }
/*]]>*/
</style>
<link rel="stylesheet" href="/css/reset.css" />
<link rel="stylesheet" href="/css/hkp.css" />
</head><body>
<div id="header">
<h1><a id="logo" href="/">PRL PKS</a></h1>
<div id="topmenu">
	<ul>
		<li><span class="menu-label">OpenPGP:</span></li>
		<li><a href="/openpgp/lookup">Search</a></li>
		<li><a href="/openpgp/add">Add</a></li>
		<li><a href="/prc/requests/delete">Delete</a></li>
		<li><a href="/pks/lookup?op=stats">Stats</a></li>
	</ul>
</div>
</div>
<h2>Search results for '{{ .Lookup.Search }}'</h2>
<b><font color="red">{{ .Msg }}</font></b>{{ end }}{{/*

*/}}{{ define "PageFooter" }}</body></html>{{ end }}{{/*

*/}}{{ define "IndexColHeader" }}<pre>Type bits/keyID     Date       User ID
</pre>{{ end }}{{/*

*/}}{{ define "IndexPubkey" }}<hr /><pre>{{ $fp := .Fingerprint }}
pub  {{ .BitLen }}{{ .Algorithm | algocode }}/<a href="/pks/lookup?op=get&amp;search=0x{{ .Fingerprint }}">{{ .ShortId | upper }}</a> {{ .Creation | date }} {{/*
*/}}{{ range $i, $uid := .UserIds }}{{/*
*/}}{{ if $i }}                               {{ $uid.Keywords }}{{/*
*/}}{{ else }}<a href="/pks/lookup?op=vindex&amp;fingerprint=on&amp;search=0x{{ $fp }}">{{ $uid.Keywords }}</a>{{ end }}
{{ end }}{{ end }}{{/*

*/}}{{ define "IndexPage" }}{{ template "PageHeader" . }}{{ $lookup := .Lookup }}{{/*
*/}}{{ template "IndexColHeader" }}{{/*
*/}}{{ range $i, $key := .Keys }}{{ template "IndexPubkey" $key }}{{/*
*/}}{{ if $lookup.Fingerprint }}{{/*
*/}}	 Fingerprint={{ $key.Fingerprint | fpformat | upper }}
{{ end }}{{/*
*/}}{{ if $lookup.Hash }}{{/*
*/}}	 MD5={{ $key.Md5 | upper }}
	 SHA256={{ $key.Sha256 | upper }}
{{ end }}{{/*
*/}}</pre>{{ end }}{{/*
*/}}{{ template "PageFooter" }}{{ end }}{{/*

*/}}{{ define "VindexColHeader" }}<pre>Type bits/keyID     cr. time   exp time   key expir
</pre>{{ end }}{{/*

*/}}{{ define "VindexPage" }}{{ template "PageHeader" . }}{{ $lookup := .Lookup }}{{/*
*/}}{{ template "VindexColHeader" . }}{{/*
*/}}{{ range $i, $key := .Keys }}<hr /><pre><strong>pub</strong>  {{ .BitLen }}{{ .Algorithm | algocode }}/<a href="/pks/lookup?op=get&amp;search=0x{{ .Fingerprint }}">{{ .ShortId | upper }}</a> {{ .Creation | date }}
{{ if $lookup.Fingerprint }}{{/*
*/}}	 Fingerprint={{ $key.Fingerprint | fpformat | upper }}
{{ end }}{{/*
*/}}{{ if $lookup.Hash }}{{/*
*/}}	 MD5={{ $key.Md5 | upper }}
	 SHA256={{ $key.Sha256 | upper }}
{{ end }}{{ range $i, $uid := $key.UserIds }}
<strong>uid</strong> <span class="uid">{{ $uid.Keywords }}</span>{{/*
*/}}{{ range $i, $sig := $uid.Signatures }}
sig <span {{ if $sig|sigWarn }}class='warn'{{ end }}>{{ $sig|sigLabel }}</span>  <a href="/pks/lookup?op=get&amp;search=0x{{ $sig.IssuerKeyId|upper }}">{{ $sig.IssuerShortId|upper }}</a> {{ $sig.Creation|date }} {{ if equal ($key.KeyId) ($sig.IssuerKeyId) }}__________ {{ $sig.Expiration|date|blank }} [selfsig]{{ else }}{{ $sig.Expiration|date|blank }} __________ <a href="/pks/lookup?op=vindex&amp;search=0x{{ $sig.IssuerKeyId|upper }}">{{ $sig.IssuerKeyId|upper }}</a>{{ end }}{{ end }}{{/*
*/}}
{{ end }}{{/* range $key.UserIds
*/}}{{ range $i, $subkey := $key.Subkeys }}
<strong>sub</strong>  {{ .BitLen }}{{ .Algorithm | algocode }}/{{ .ShortId | upper }} {{ .Creation | date }}{{ range $i, $sig := $subkey.Signatures }}
sig <span {{ if $sig|sigWarn }}class='warn'{{ end }}>{{ $sig|sigLabel }}</span>  <a href="/pks/lookup?op=get&amp;search=0x{{ $sig.IssuerKeyId|upper }}">{{ $sig.IssuerShortId|upper }}</a> {{ $sig.Creation|date }} {{ if equal ($key.KeyId) ($sig.IssuerKeyId) }}__________ {{ $sig.Expiration|date|blank }} []{{ else }}{{ $sig.Expiration|date|blank }} __________ {{ $sig.IssuerShortId|upper }}{{ end }}{{ end }}{{/*
*/}}
{{ end }}{{/* range .$key.Subkeys
*/}}{{ end }}{{/* range .Keys
*/}}{{ template "PageFooter" }}{{ end }}{{/*
*/}}{{ if .Verbose }}{{ template "VindexPage" . }}{{ else }}{{ template "IndexPage" . }}{{ end }}`

var indexPageTmpl *ht.Template

const indexMrTmplSrc = `{{ define "IndexMr" }}{{/*
*/}}info:1:1{{/*
*/}}{{ $lookup := .Lookup }}{{ range $keyi, $key := .Keys }}
pub:{{ if $lookup.Fingerprint }}{{ $key.Fingerprint|upper }}{{ else }}{{ $key.ShortId|upper }}{{ end }}:{{ $key.Algorithm }}:{{ $key.BitLen }}:{{ $key.Creation.Unix }}:{{ $key.Expiration|expunix }}:{{ range $uidi, $uid := $key.UserIds }}
uid:{{ $uid.Keywords|escapeColons }}:{{ (maxSelfSig $key $uid.Signatures).Creation.Unix }}:{{ (maxSelfSig $key $uid.Signatures).Expiration|expunix }}:{{ end }}{{ end }}{{/*
*/}}{{ end }}{{/*

*/}}{{ template "IndexMr" . }}`

var indexMrTmpl *tt.Template

func fingerprintFormat(fp string) string {
	var result []rune
	for i, r := range fp {
		if i > 0 {
			if i%4 == 0 {
				result = append(result, ' ')
			}
			if i%20 == 0 && len(fp) == 40 {
				result = append(result, ' ')
			}
		}
		result = append(result, r)
	}
	return string(result)
}

func escapeColons(s string) string {
	var result []rune
	for _, r := range s {
		if r == ':' {
			result = append(result, []rune(`\x3a`)...)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

func sigWarn(sig *Signature) bool {
	if time.Now().Unix() > sig.Expiration.Unix() {
		return true
	}
	switch sig.SigType {
	case 0x28:
		return true
	case 0x30:
		return true
	}
	return false
}

func sigLabel(sig *Signature) string {
	sigName := "sig"
	if time.Now().Unix() > sig.Expiration.Unix() {
		return " exp "
	}
	switch sig.SigType {
	case 0x10:
		return fmt.Sprintf(" %s ", sigName)
	case 0x11:
		return fmt.Sprintf(" %s1", sigName)
	case 0x12:
		return fmt.Sprintf(" %s2", sigName)
	case 0x13:
		return fmt.Sprintf(" %s3", sigName)
	case 0x18:
		return "sbind"
	case 0x28:
		return "revok"
	case 0x30:
		return "revok"
	}
	return sigName
}

func AlgorithmCode(algorithm int) string {
	switch packet.PublicKeyAlgorithm(algorithm) {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		return "R"
	case packet.PubKeyAlgoElGamal:
		return "g"
	case packet.PubKeyAlgoDSA:
		return "D"
	}
	return fmt.Sprintf("[%d]", algorithm)
}

func init() {
	funcs := map[string]interface{}{
		"algocode":     AlgorithmCode,
		"fpformat":     fingerprintFormat,
		"upper":        strings.ToUpper,
		"maxSelfSig":   maxSelfSig,
		"escapeColons": escapeColons,
		"equal":        func(s, r string) bool { return s == r },
		"sigLabel":     sigLabel,
		"sigWarn":      sigWarn,
		"expunix": func(t time.Time) string {
			if t.Unix() == NeverExpires.Unix() {
				return ""
			}
			return fmt.Sprintf("%d", t.Unix())
		},
		"blank": func(s string) string {
			if s == "" {
				return "__________"
			}
			return s
		},
		"date": func(t time.Time) string {
			if t.Unix() == NeverExpires.Unix() {
				return ""
			}
			return t.Format("2006-01-02")
		}}
	indexPageTmpl = ht.Must(ht.New("indexPage").Funcs(funcs).Parse(indexPageTmplSrc))
	indexMrTmpl = tt.Must(tt.New("indexPage").Funcs(funcs).Parse(indexMrTmplSrc))
}

//PRC Edit Start
type IndexResponse struct {
	Lookup    *hkp.Lookup
	Keys      []*Pubkey
	Verbose   bool
	Err       error
	Delegated bool   //IF lookup was delegated to other PKS Server then it is true
	Msg       string //Message to be shown on html index page
}

func (r *IndexResponse) Error() error {
	return r.Err
}

func (r *IndexResponse) WriteTo(w http.ResponseWriter) error {
	for _, key := range r.Keys {
		Sort(key)
	}
	if r.Lookup.MachineReadable() {
		w.Header().Add("Content-Type", "text/plain")
		r.Err = indexMrTmpl.Execute(w, r)
	} else {
		w.Header().Add("Content-Type", "text/html")
		//PRC Start
		if r.Delegated {
			r.Msg = " Warning!! Key not found on PRL PKS. These key/s were fetched from " + Config().GetStringDefault("authority.delegateAddress", "pool.sks-keyservers.net:11371") +
				". These key/s are not verified by PRL PKS,and hence the users have to verify the keys themselves. "
		}
		//PRC End
		r.Err = indexPageTmpl.Execute(w, r)
	}
	return r.Err
}

//PRC Edit END
