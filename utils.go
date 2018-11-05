package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// Formatting multierror results
func formatErrors(es []error) string {
	if len(es) == 1 {
		return fmt.Sprintf("request contained 1 error: %s", es[0])
	}

	points := make([]string, len(es))
	for i, err := range es {
		points[i] = fmt.Sprintf("%s", err)
	}

	return fmt.Sprintf(
		"request contained %d errors: %s",
		len(es), strings.Join(points, ", "))
}

type pageContextKey string

var pageKey = pageContextKey("page")

func paginate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unsafePageStr := strings.Join(r.URL.Query()["page"], "")
		sanitizedPageInt, _ := strconv.Atoi(unsafePageStr)
		ctx := context.WithValue(r.Context(), pageKey, sanitizedPageInt)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func joinStringSlice(strs []string) string {
	var sb strings.Builder
	for _, str := range strs {
		sb.WriteString(str)
	}
	return sb.String()
}

func validIDFormat(id string) bool {
	idParts := strings.Split(id, ":")
	idRxp := regexp.MustCompile("^[\\w\\-]+$") //base64 string
	if len(idParts) == 3 && idParts[0] == "did" && idParts[1] == "jlinc" && idRxp.MatchString(idParts[2]) {
		return true
	}
	return false
}

func decryptRegSecret(c string, n string, pk string, sk string) ([]byte, bool) {
	cyphertext := b64Decode(c)
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

func zeroPrefixed(c []byte, n int) bool {
	prefixed := true
	for i := 0; i < n; i++ {
		if c[i] != 0 {
			prefixed = false
		}
	}
	return prefixed
}

func getHash(j string) []byte {
	h := sha256.New()
	h.Write([]byte(j))
	return h.Sum(nil)
}

func b64Decode(s string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(s)
	return decoded
}

func b64Encode(h []byte) string {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.RawURLEncoding, &buf)
	encoder.Write(h)
	encoder.Close()
	return buf.String()
}
