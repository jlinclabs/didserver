package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestIndexPage(t *testing.T) {
	var Conf Config //it deliberately shadows declaration at didserver.go:44
	type TestHomepageContent struct {
		masterPublicKey string
	}

	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
	}
	MasterPublicKey = Conf.Keys.Public

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(indexstr)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the content-type is what we expect.
	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	// Check content
	var testHomepageContent TestHomepageContent
	_ = json.Unmarshal([]byte(rr.Body.String()), &testHomepageContent)

	if testHomepageContent.masterPublicKey != MasterPublicKey {
		t.Errorf("Homepage returned unexpected key: got %s want %s", testHomepageContent.masterPublicKey, MasterPublicKey)
	}
}
