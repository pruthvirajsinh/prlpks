PrcIdSigner
===========

It signs an ID in GPG Public Key.It works directly on Ascii armor of public and
private keys which makes it easy to work with.It also provides easy to use methods to
Change Public Keys from openpgp.Entity to Armor and vice versa.

Current Implemetation of SignIdentity in Go is faulty and generates ID signature that
is not recognized as valid by other GPG softwares.

Hence this implements patch provided to resolve issue no. 7371 
https://code.google.com/p/go/issues/detail?id=7371.
