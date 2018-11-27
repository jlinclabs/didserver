package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	_ "github.com/lib/pq"
)

func TestNoSupersedeInput(t *testing.T) {
	input := strings.NewReader("")

	req, err := http.NewRequest("POST", "/supersede", input)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(supersedeDID)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnprocessableEntity {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnprocessableEntity)
	}

	if ctype := rr.Header().Get("Content-Type"); ctype != "text/plain; charset=utf-8" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "text/plain; charset=utf-8")
	}

	expected := `Not valid JSON
`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestBadSupersedeNoSupersedee(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}
	connStr := Conf.Database.ConnectionString
	var err error
	DB, err = sql.Open("postgres", connStr)
	defer DB.Close()
	if err != nil {
		log.Fatal(err)
		return
	}

	Conf.IsTest = true //so it doesn't test the timestamp

	// enter test data in the DB
	stmt, _ := DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              secret_cypher,
                                              secret_nonce,
                                              challenge,
                                              status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`)
	_, err = stmt.Exec("did:jlinc:31UiO0CMrGLoAQ35A25dg7zQb3uCkSkpj87gdRD9H5w",
		"did:jlinc:31UiO0CMrGLoAQ35A25dg7zQb3uCkSkpj87gdRD9H5w",
		"xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"Vk3kVIvGFV4Ew5m3xJ43N8T5WNFX7qjMOSrJ3Gu4m3E",
		"AAAAAAAAAAAAAAAAAAAAAJNdfP98pEJQ0M1RpLehjw2798z5FfbAeJErbmYxrYxJwiNqX1laQbmxp5gC2KOPgKw2KY7qHLfvdxBO_yV8b4gviwO3CODi-FQ2E7Q55fCf",
		"Q2CMu1V6RK9YyvV-ExJD1UVIQt20qVGO",
		"e36f5aac97038c79fe1352d6c81e930885267601c133f3b3bf94e54a4df4db5d",
		"verified")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	input := `{"did":{"@context":"https://w3id.org/did/v1","id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","created":"2018-11-25T21:51:16.366Z","publicKey":[{"id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#signing","type":"ed25519","owner":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","publicKeyBase64":"jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic"},{"id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#encrypting","type":"curve25519","owner":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","publicKeyBase64":"HdwpfwsfaldCWH0wtNEjQInXawQ0sHBIfKsrVufzvFc"}]},"signature":"dO0MyxqfSXbgczRjt5FbkL6dYwh7x11LqKuJ2auORECDspJte5XyhoVpJo8tIo3L2pxPhky_mvNrTM7wsW5-BA","supersedes":"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI"}`
	inputReader := strings.NewReader(input)

	req, err := http.NewRequest("POST", "/supersede", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(supersedeDID)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	expected := `{"status":"item to supersede not found"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}

	// delete previous entries from the test database
	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()
}

func TestBadSupersedeStatus(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}
	connStr := Conf.Database.ConnectionString
	var err error
	DB, err = sql.Open("postgres", connStr)
	defer DB.Close()
	if err != nil {
		log.Fatal(err)
		return
	}

	Conf.IsTest = true //so it doesn't test the timestamp

	// enter test data in the DB
	stmt, _ := DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              secret_cypher,
                                              secret_nonce,
                                              challenge,
                                              status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`)
	_, err = stmt.Exec("did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"Vk3kVIvGFV4Ew5m3xJ43N8T5WNFX7qjMOSrJ3Gu4m3E",
		"AAAAAAAAAAAAAAAAAAAAAJNdfP98pEJQ0M1RpLehjw2798z5FfbAeJErbmYxrYxJwiNqX1laQbmxp5gC2KOPgKw2KY7qHLfvdxBO_yV8b4gviwO3CODi-FQ2E7Q55fCf",
		"Q2CMu1V6RK9YyvV-ExJD1UVIQt20qVGO",
		"e36f5aac97038c79fe1352d6c81e930885267601c133f3b3bf94e54a4df4db5d",
		"revoked")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	input := `{"did":{"@context":"https://w3id.org/did/v1","id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","created":"2018-11-25T21:51:16.366Z","publicKey":[{"id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#signing","type":"ed25519","owner":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","publicKeyBase64":"jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic"},{"id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#encrypting","type":"curve25519","owner":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","publicKeyBase64":"HdwpfwsfaldCWH0wtNEjQInXawQ0sHBIfKsrVufzvFc"}]},"signature":"dO0MyxqfSXbgczRjt5FbkL6dYwh7x11LqKuJ2auORECDspJte5XyhoVpJo8tIo3L2pxPhky_mvNrTM7wsW5-BA","supersedes":"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI"}`
	inputReader := strings.NewReader(input)

	req, err := http.NewRequest("POST", "/supersede", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(supersedeDID)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusConflict {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusConflict)
	}

	expected := `{"status":"item to supersede not active"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}

	// delete previous entries from the test database
	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()
}

func TestGoodSupersedeInput(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}
	connStr := Conf.Database.ConnectionString
	var err error
	DB, err = sql.Open("postgres", connStr)
	defer DB.Close()
	if err != nil {
		log.Fatal(err)
		return
	}

	Conf.IsTest = true //so it doesn't test the timestamp

	// enter test data in the DB
	stmt, _ := DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              secret_cypher,
                                              secret_nonce,
                                              challenge,
                                              status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`)
	_, err = stmt.Exec("did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"Vk3kVIvGFV4Ew5m3xJ43N8T5WNFX7qjMOSrJ3Gu4m3E",
		"AAAAAAAAAAAAAAAAAAAAAJNdfP98pEJQ0M1RpLehjw2798z5FfbAeJErbmYxrYxJwiNqX1laQbmxp5gC2KOPgKw2KY7qHLfvdxBO_yV8b4gviwO3CODi-FQ2E7Q55fCf",
		"Q2CMu1V6RK9YyvV-ExJD1UVIQt20qVGO",
		"e36f5aac97038c79fe1352d6c81e930885267601c133f3b3bf94e54a4df4db5d",
		"verified")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	input := `{"did":{"@context":"https://w3id.org/did/v1","id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","created":"2018-11-25T21:51:16.366Z","publicKey":[{"id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#signing","type":"ed25519","owner":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","publicKeyBase64":"jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic"},{"id":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#encrypting","type":"curve25519","owner":"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic","publicKeyBase64":"HdwpfwsfaldCWH0wtNEjQInXawQ0sHBIfKsrVufzvFc"}]},"signature":"dO0MyxqfSXbgczRjt5FbkL6dYwh7x11LqKuJ2auORECDspJte5XyhoVpJo8tIo3L2pxPhky_mvNrTM7wsW5-BA","supersedes":"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI"}`
	inputReader := strings.NewReader(input)

	req, err := http.NewRequest("POST", "/supersede", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(supersedeDID)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	goodBody := regexp.MustCompile(`^\{"id":"did:jlinc:[\w\-]+", "challenge":"[\w\-]+"\}$`)
	if !goodBody.MatchString(rr.Body.String()) {
		t.Errorf("handler returned unexpected body: got %v", rr.Body.String())
	}

	var id, root, did, status string
	expectedID := "did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic"
	expectedRoot := "did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI"
	expectedStatus := "init"

	row := DB.QueryRow("select id, root, did, status FROM didstore ORDER BY created desc")
	err = row.Scan(&id, &root, &did, &status)

	// Unmarshal and re-Marshal the input and the DB's did value so they can be compared
	type RawDid struct {
		DID interface{} `json:"did"`
	}
	var expectedDID RawDid
	json.Unmarshal([]byte(input), &expectedDID)
	var rawFromDB RawDid
	json.Unmarshal([]byte(did), &rawFromDB)

	expectedjs, _ := json.Marshal(expectedDID)
	rawjs, _ := json.Marshal(rawFromDB)

	if string(rawjs) != string(expectedjs) {
		t.Errorf("database returned unexpected did: got %+v want %+v", string(rawjs), string(expectedjs))
	}

	if id != expectedID || root != expectedRoot || status != expectedStatus {
		t.Errorf("database returned unexpected value(s): got %q, %q, %q want %q, %q, %q with error %v", id, root, status, expectedID, expectedRoot, expectedStatus, err)
	}

	// delete previous entries from the test database
	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()
}
