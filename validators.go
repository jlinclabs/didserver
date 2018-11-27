package main

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

func getValidID(id string) (string, bool) {
	idParts := strings.Split(id, ":")
	idRxp := regexp.MustCompile(`^[\w\-]+$`) //base64 string
	if len(idParts) == 3 && idParts[0] == "did" && idParts[1] == "jlinc" && idRxp.MatchString(idParts[2]) {
		return idParts[2], true
	}
	return "", false
}

func decryptRegSecret(c string, n string, pk string, sk string) ([]byte, bool) {
	cyphertext := b64Decode(c)
	if len(cyphertext) < 16 {
		return nil, false //guard against empty cyphertext
	}

	// box.Open requires nonce to be type *[24]byte and keys to be type *[32]byte
	var nonce [24]byte
	var senderPubkey [32]byte
	var serverSecret [32]byte
	copy(nonce[:], b64Decode(n))
	copy(senderPubkey[:], b64Decode(pk))
	copy(serverSecret[:], b64Decode(sk))

	// node-sodium/libsodium prefixes the cyphertext with 16 bytes of zeros (sodium.crypto_box_BOXZEROBYTES).
	// box.Open doesn't seem to like this, so we strip them off.
	if prefixed := zeroPrefixed(cyphertext, 16); prefixed {
		cyphertext = cyphertext[16:]
	}

	secret, ok := box.Open(nil, cyphertext, &nonce, &senderPubkey, &serverSecret)
	return secret, ok
}

func getJwtSecret(id string) (secret []byte, err error) {
	var (
		cypher           string
		nonce            string
		encryptingPubkey string
	)
	err = DB.QueryRow("SELECT secret_cypher, secret_nonce, encrypting_pubkey FROM didstore WHERE id = $1", id).Scan(&cypher, &nonce, &encryptingPubkey)
	if err != nil {
		return nil, err
	}
	secret, ok := decryptRegSecret(cypher, nonce, encryptingPubkey, Conf.Keys.Secret)
	if !ok {
		return nil, fmt.Errorf("Unable to decrypt registration secret")
	}

	return secret, nil
}

func getRootJwtSecret(id string) (secret []byte, err error) {
	var (
		cypher           string
		nonce            string
		encryptingPubkey string
	)
	// get the root record
	err = DB.QueryRow("SELECT r.secret_cypher, r.secret_nonce, r.encrypting_pubkey FROM didstore AS s JOIN didstore AS r ON s.root = r.id WHERE s.id = $1", id).Scan(&cypher, &nonce, &encryptingPubkey)
	if err != nil {
		return nil, err
	}

	secret, ok := decryptRegSecret(cypher, nonce, encryptingPubkey, Conf.Keys.Secret)
	if !ok {
		return nil, fmt.Errorf("Unable to decrypt registration secret")
	}

	return secret, nil
}
