// prcTester project main.go
package main

import (
	"fmt"
	"github.com/kennygrant/sanitize"
	"regexp"
	"strings"
)

func PtagToString(htmlString string) (output string, err error) {
	reg1, err1 := regexp.Compile("<[^>]*>")
	if err1 != nil {
		err = err1
		return
	}

	reg2, err2 := regexp.Compile("<[p^>]*>.*</p>")
	//regexp.MustCompile()
	if err2 != nil {
		err = err2
		return
	}

	s := strings.Replace(htmlString, "\n", "", -1)

	matched := reg2.FindAllString(s, -1)
	if matched == nil {
		fmt.Println("No Match")
	} else {
		fmt.Println(matched)
	}
	safe := ""
	for _, m := range matched {
		safe += reg1.ReplaceAllString(m, " ")
	}
	output = safe
	return
}
func main() {

	//String target = someString.replaceAll("(?i)<td[^>]*>", " ").replaceAll("\\s+", " ").trim();
	msg, _ := PtagToString(htmlString)

	fmt.Println("Regexp \n", msg)

	fmt.Println("sanitize\n", sanitize.HTML(htmlString))

}

const htmlString = `


<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>PRL PKS | Delete Public Keys</title>

<link rel="stylesheet" href="/css/reset.css" />
<link rel="stylesheet" href="/css/hkp.css" />

</head>
<body>
<div id="container">

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

<div id="main">

<h2>Delete Public Keys</h2>

<p>A request for same key has already been made.Please Check your email user1@mail.hom.prc</p>


</div>
</div>

<div id="footer">
<div id="copyleft">PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).</div>
</div>

</body>
</html>


`
