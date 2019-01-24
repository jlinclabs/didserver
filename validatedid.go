package main

import (
	"errors"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/ed25519"
)

func validateDIDparams(registration *Registration) *multierror.Error {
	var result *multierror.Error
	if registration.DID.AtContext != Conf.At.Context {
		result = multierror.Append(result, errors.New("@context missing or incorrect"))
	}

	if _, ok := getValidID(registration.DID.ID); !ok {
		result = multierror.Append(result, errors.New("id must be did:jlinc:{base64 encoded string}"))
	}

	// check the timestamp as long as Conf.IsTest is not true
	if !Conf.IsTest {
		t, err := time.Parse(time.RFC3339, registration.DID.CreatedAt)
		if err != nil {
			result = multierror.Append(result, errors.New("created must be in valid RFC3339 format"))
		}
		// we'll allow the timestamp to be from 10 minutes before now (for latency) to 1 minute after now (for clock error)
		if time.Since(t) > time.Minute*10 || time.Until(t) > time.Minute {
			result = multierror.Append(result, errors.New("DID timestamp is out of bounds"))
		}
	}
	return result
}

func getDIDkeys(registration *Registration) *multierror.Error {
	// get the signing and encrypting public keys
	var result *multierror.Error
	for _, key := range registration.DID.PublicKeys {
		idParts := strings.Split(key.ID, "#")
		if len(idParts) > 1 {
			if idParts[1] == "signing" {
				if key.Owner != registration.DID.ID {
					result = multierror.Append(result, errors.New("Signing key owner incorrect"))
				}
				if key.Type != "ed25519" {
					result = multierror.Append(result, errors.New("Signing key type incorrect"))
				}
				registration.SigningKey = key.PublicKeyBase64
			}
			if idParts[1] == "encrypting" {
				if key.Owner != registration.DID.ID {
					result = multierror.Append(result, errors.New("Encrypting key owner incorrect"))
				}
				if key.Type != "curve25519" {
					result = multierror.Append(result, errors.New("Encrypting key type incorrect"))
				}
				registration.EncryptingKey = key.PublicKeyBase64
			}
		}
	}
	return result
}

func validateDIDsignature(registration *Registration) *multierror.Error {
	var result *multierror.Error
	signingPkey := b64Decode(registration.SigningKey)
	if len(signingPkey) != ed25519.PublicKeySize {
		result = multierror.Append(result, errors.New("signing public key missing or size incorrect"))
	} else {
		//check registration.Signature
		signed := registration.DID.ID + "." + registration.DID.CreatedAt
		signedHashed := getHash(signed)
		sig := b64Decode(registration.Signature)
		if sigVerified := ed25519.Verify(signingPkey, signedHashed, sig); !sigVerified {
			result = multierror.Append(result, errors.New("signature did not verify"))
		}
	}
	return result
}

func validateDIDsecret(registration *Registration) *multierror.Error {
	var result *multierror.Error
	if len(b64Decode(registration.EncryptingKey)) != 32 {
		result = multierror.Append(result, errors.New("encrypting public key missing or size incorrect"))
	} else {
		//check that registration.Secret.Cyphertext can be decoded
		_, ok := decryptRegSecret(registration.Secret.Cyphertext, registration.Secret.Nonce, registration.EncryptingKey, Conf.Keys.Secret)
		if !ok {
			result = multierror.Append(result, errors.New("secret did not decrypt correctly"))
		}
	}
	return result
}
