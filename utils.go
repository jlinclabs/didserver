package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/shengdoushi/base58"
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

func checkAtContext(atCtx string) int {
	contextVersion := 0
	switch atCtx {
	case Conf.At.ContextV1:
		contextVersion = 1
	case Conf.At.ContextV2:
		contextVersion = 2
	}
	return contextVersion
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

func getByteHash(j []byte) []byte {
	h := sha256.New()
	h.Write(j)
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

func b58Decode(s string) []byte {
	decoded, _ := base58.Decode(s, base58.BitcoinAlphabet)
	return decoded
}

func b58Encode(h []byte) string {
	return base58.Encode(h, base58.BitcoinAlphabet)
}

func b58tob64(s string) string {
	return b64Encode(b58Decode(s))
}
