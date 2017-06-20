package tuf

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"

	"github.com/pkg/errors"
)

var errSignatureCheckFailed = errors.New("signature check failed")
var errSignatureThresholdNotMet = errors.New("signature threshold not met")
var errInvalidKeyType = errors.New("invalid key type")
var errHashMismatch = errors.New("hash of file was not correct")

type verifier interface {
	verify(digest []byte, key *Key, sig *Signature) error
}

type signingMethodECDSA struct{}

func newVerifier(method signingMethod) (verifier, error) {
	if method == methodECDSA {
		return &signingMethodECDSA{}, nil
	}
	return nil, errors.Errorf("signing method %q is not supported", method)
}

func (sm *signingMethodECDSA) verify(signed []byte, key *Key, sig *Signature) error {
	var publicKey crypto.PublicKey

	switch key.KeyType {
	case keyTypeECDSAx509:
		rawBuff, err := key.base64Decoded()
		if err != nil {
			return errors.Wrap(err, "base 64 decoding public key")
		}
		pemCert, _ := pem.Decode(rawBuff)
		if pemCert == nil {
			return errors.New("failed to decode PEM x509 cert")
		}
		cert, err := x509.ParseCertificate(pemCert.Bytes)
		if err != nil {
			return errors.Wrap(err, "ecdsa verification")
		}
		publicKey = cert.PublicKey
	case keyTypeECDSA:
		rawBuff, err := key.base64Decoded()
		if err != nil {
			return errors.Wrap(err, "base 64 decoding public key")
		}
		publicKey, err = x509.ParsePKIXPublicKey(rawBuff)
		if err != nil {
			return errors.Wrap(err, "failed to parse public key in ecdsa verify")
		}
	default:
		return errInvalidKeyType
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("expected ecdsa public key, got something else")
	}
	expectedOctetLen := 2 * ((ecdsaPublicKey.Params().BitSize + 7) >> 3)
	sigBuff, err := sig.base64Decoded()
	if err != nil {
		return errors.Wrap(err, "base 64 decoding signature failed")
	}
	sigLen := len(sigBuff)
	if sigLen != expectedOctetLen {
		return errors.New("signature length is incorrect")
	}

	rBuff, sBuff := sigBuff[:sigLen/2], sigBuff[sigLen/2:]
	r := new(big.Int).SetBytes(rBuff)
	s := new(big.Int).SetBytes(sBuff)
	digest := sha256.Sum256(signed)
	if !ecdsa.Verify(ecdsaPublicKey, digest[:], r, s) {
		return errSignatureCheckFailed
	}

	return nil
}

type hashTester struct {
	encodedHash string
	hasher      func([]byte) []byte
}

func (c *hashTester) test(b []byte) error {
	hash, err := base64.StdEncoding.DecodeString(c.encodedHash)
	if err != nil {
		return errors.Wrap(err, "decoding base64 file integrity check")
	}
	match := bytes.Equal(c.hasher(b), hash)
	if !match {
		return errHashMismatch
	}
	return nil
}
