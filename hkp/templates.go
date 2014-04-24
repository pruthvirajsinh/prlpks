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
	"html/template"
	"strings"
	"time"
)

const footerTmplSrc = `
{{define "page_footer"}}
<div id="footer">
<div id="copyleft">PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on prlpks(https://github.com/pruthvirajsinh/prlpks) by Casey Marshall, copyright 2013(GNU GPL v3).</div>
</div>
{{end}}`

const headTmplSrc = `
{{define "head"}}
<link rel="stylesheet" href="/css/reset.css" />
<link rel="stylesheet" href="/css/hkp.css" />
{{end}}`

const headerTmplSrc = `
{{define "page_header"}}
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
{{end}}`

const layoutTmplSrc = `
{{define "top"}}
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>{{template "title"}}</title>
{{template "head"}}
</head>
<body>
<div id="container">
{{template "page_header"}}
<div id="main">
{{end}}

{{define "bottom"}}
</div><!-- main -->
</div><!-- container -->
{{template "page_footer"}}
</body>
</html>
{{end}}

{{define "layout"}}
{{template "top" .}}
{{template "page_content" .}}
{{template "bottom" .}}
{{end}}`

const addFormTmplSrc = `
{{define "title"}}PRL PKS | Add Public Key{{end}}

{{define "page_content"}}
<h2 class="pks-add" style="text-align: center;">Add Public Key</h2>
<p style="text-align: center;">Paste the ASCII-armored public key block into the form below.</p>
<form class="pks-add" action="/pks/add" method="post" style="text-align: center;">
	<div>
		<textarea name="keytext" cols="66" rows="20"></textarea>
	</div>
	<div>
		<input id="add_submit" type="submit" value="Add Public Key"></input>
	</div>
</form>
<p style="text-align: center;">You can only add the Key which belongs to you.A verification e-mail will be sent to the owner of the key.Without verification a key can not be added to the server.</p>
{{end}}`

const addResultTmplSrc = `
{{define "title"}}PRL PKS | Updated Public Keys{{end}}

{{define "page_content"}}
<h2>Updated Public Keys</h2>
{{range .Changes}}
<p>{{.ChangeMessage}}</p>
{{ if .Fingerprint }}
<p><a href="/pks/lookup?op=index&search=0x{{.Fingerprint}}">{{.}}</a></p>
{{end}}

{{end}}
{{end}}`

const searchFormTmplSrc = `
{{define "title"}}PRL PKS | Search OpenPGP Public Keys{{end}}

{{define "page_content"}}
<h2 class="pks-search">OpenPGP Search</h2>
<form class="pks-search" method="post">
	<div>
		<input name="search" type="search"></input>
	</div>
	<div>
		<input id="search_submit" formaction="/pks/lookup?op=index" type="submit" value="Public Key Search"></input>
		
	</div>
</form>
<p class="pks-search">Enter e-mail ID or Key ID of the public key that you want to search.</p>
{{end}}`

const statsTmplSrc = `
{{define "title"}}PRL PKS | Server Status{{end}}

{{define "page_content"}}
<h2>Server Status</h2>
<table>
<tr><th>Hostname:</th><td>{{.Hostname}}</td></tr>
<tr><th>Port:</th><td>{{.Port}}</td></tr>
<tr><th>Version:</th><td>{{.Version}}</td></tr>
</table>
{{if .PksPeers}}
<h2>Outgoing Mailsync Peers</h2>
<table>
<tr><th>Email Address</th><th>Last Synchronized</th></tr>
{{range .PksPeers}}
<tr><td>{{.Addr}}</td><td>{{timef .LastSync}}</td></tr>
{{end}}
</table>
{{end}}
<h2>Statistics</h2>
<table>
<tr><th>Total number of keys:</th><td>{{.TotalKeys}}</td></tr>
</table>
{{if .KeyStatsHourly}}
<h3>Keys loaded in the last 24 hours</h3>
<table>
<tr><th>Hour</th><th>New</th><th>Updated</th></tr>
{{range .KeyStatsHourly}}
<tr><td>{{.Hour}}</td><td>{{.Created}}</td><td>{{.Modified}}</td></tr>
{{end}}
</table>
{{end}}
{{if .KeyStatsDaily}}
<h3>Keys loaded in the last 7 days</h3>
<table>
<tr><th>Day</th><th>New</th><th>Updated</th></tr>
{{range .KeyStatsDaily}}
<tr><td>{{.Day}}</td><td>{{.Created}}</td><td>{{.Modified}}</td></tr>
{{end}}
</table>
{{end}}
{{end}}`

//PRC Start
const deleteFormTmplSrc = `
{{define "title"}}PRL PKS | Delete OpenPGP Public Keys{{end}}

{{define "page_content"}}
<h2 class="pks-search">Delete Key</h2>

<form class="pks-search" method="post">
	<div>
		<input name="deleteTB" type="search" style="width:60%;"></input>
	</div>
	<div>
		<input id="delete_submit" formaction="/prc/delete" type="submit" value="Delete Public Key"></input>
		
	</div>
</form>
<p class="pks-search">Enter e-mail ID or Key ID of the key to be deleted.</p>
<p class="pks-search">You can only delete Key which belongs to you.A verification e-mail will be sent to the owner of the key.Without verification a key can not be deleted.</p>
{{end}}`

const deleteResultTmplSrc = `
{{define "title"}}PRL PKS | Delete Public Keys{{end}}

{{define "page_content"}}
<h2>Delete Public Keys</h2>
{{range .DeleteResults}}
<p>{{.DeleteMessage}}</p>
{{end}}
{{end}}`

//PRC END

// baseTmplSrcs contains common templates that need to be defined
// for all PRL PKS HKP templates.
var BaseTemplateSrcs = []string{
	headTmplSrc, headerTmplSrc, footerTmplSrc,
	layoutTmplSrc}

// SearchFormTemplate is used to render the default search form at '/'
var SearchFormTemplate *template.Template

// AddFormTemplate is used to render the form to add a key.
var AddFormTemplate *template.Template

// AddResultTemplate displays the fingerprints of updated keys.
var AddResultTemplate *template.Template

// PksIndexTemplate is used to render the op=index and op=vindex
// responses when not in machine readable mode.
var PksIndexTemplate *template.Template

// StatsTemplate renders the op=stats page
var StatsTemplate *template.Template

//PRC START
// DeleteFormTemplate is used to render the form to delete a key.
var DeleteFormTemplate *template.Template

// AddResultTemplate displays the fingerprints of updated keys.
var DeleteResultTemplate *template.Template

//PRC END

func mustParseHkpTemplate(src string) *template.Template {
	return template.Must(template.New("placeholder").Parse(strings.Join(
		append(BaseTemplateSrcs, src), "")))
}

func init() {
	SearchFormTemplate = mustParseHkpTemplate(searchFormTmplSrc)
	AddFormTemplate = mustParseHkpTemplate(addFormTmplSrc)
	//PRC Start
	DeleteFormTemplate = mustParseHkpTemplate(deleteFormTmplSrc)
	DeleteResultTemplate = mustParseHkpTemplate(deleteResultTmplSrc)
	//PRC End
	AddResultTemplate = mustParseHkpTemplate(addResultTmplSrc)
	StatsTemplate = template.Must(template.New("placeholder").Funcs(
		template.FuncMap{"timef": func(ts int64) string {
			tm := time.Unix(0, ts)
			return tm.Format(time.RFC3339)
		}}).Parse(strings.Join(append(BaseTemplateSrcs, statsTmplSrc), "")))
}
