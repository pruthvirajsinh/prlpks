package PrcIdSigner

import (
	. "code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/errors"
	"code.google.com/p/go.crypto/openpgp/packet"
	"log"
)

// PRCSignIdentity adds a signature to e, from signer, attesting that identity is
// associated with e. The provided identity must already be an element of
// e.Identities and the private key of signer must have been decrypted if
// necessary.
// If config is nil, sensible defaults will be used.
// Note:It is custom implementation based on patch provided to resolve issue no. 7371
//https://code.google.com/p/go/issues/detail?id=7371.
func (e PrcEntity) PRCSignIdentity(identity string, signer PrcEntity, config *packet.Config) error {
	if signer.PrivateKey == nil {
		return errors.InvalidArgumentError("signing Entity must have a private key")
	}
	if signer.PrivateKey.Encrypted {
		return errors.InvalidArgumentError("signing Entity's private key must be decrypted")
	}
	ident, ok := e.Identities[identity]
	if !ok {
		return errors.InvalidArgumentError("given identity string not found in Entity")
	}
	log.Println("Entity : ", e)
	sig := &packet.Signature{
		SigType:      packet.SigTypeGenericCert,
		PubKeyAlgo:   signer.PrivateKey.PubKeyAlgo,
		Hash:         config.Hash(),
		CreationTime: config.Now(),
		IssuerKeyId:  &signer.PrivateKey.KeyId}

	//Was in original: if err := sig.SignKey(e.PrimaryKey, signer.PrivateKey, config); err != nil {
	//Suggested in patch
	if err := sig.SignUserId(ident.UserId.Id, e.PrimaryKey, signer.PrivateKey, config); err != nil {
		return err
	}
	ident.Signatures = append(ident.Signatures, sig)
	return nil
}

//PRCSignIdentityLifeTime is same as PRCSignIdentity but with a Lifetime of the signature in seconds
func (e PrcEntity) PRCSignIdentityLifeTime(identity string, signer PrcEntity, config *packet.Config, lifeTime uint32) error {
	if signer.PrivateKey == nil {
		return errors.InvalidArgumentError("signing Entity must have a private key")
	}
	if signer.PrivateKey.Encrypted {
		return errors.InvalidArgumentError("signing Entity's private key must be decrypted")
	}
	ident, ok := e.Identities[identity]
	if !ok {
		return errors.InvalidArgumentError("given identity string not found in Entity")
	}
	log.Println("Entity : ", e)
	sig := &packet.Signature{
		SigType:         packet.SigTypeGenericCert,
		PubKeyAlgo:      signer.PrivateKey.PubKeyAlgo,
		Hash:            config.Hash(),
		CreationTime:    config.Now(),
		IssuerKeyId:     &signer.PrivateKey.KeyId,
		SigLifetimeSecs: &lifeTime} //In Seconds

	//Was in original: if err := sig.SignKey(e.PrimaryKey, signer.PrivateKey, config); err != nil {
	//Suggested in patch
	if err := sig.SignUserId(ident.UserId.Id, e.PrimaryKey, signer.PrivateKey, config); err != nil {
		return err
	}
	ident.Signatures = append(ident.Signatures, sig)
	return nil
}

type PrcEntity struct {
	*Entity
}
