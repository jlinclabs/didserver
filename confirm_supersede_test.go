package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	_ "github.com/lib/pq"
)

func TestBadSupersedeConfirm(t *testing.T) {
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

	// enter supersedee data in the DB
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
		t.Errorf("Insert into db error-e: %q", err)
	}
	// enter superseder data in the DB
	stmt, _ = DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              challenge,
                                              supersedes,
                                              status) VALUES ($1, $2, $3, $4, $5, $6, $7)`)
	_, err = stmt.Exec("did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic",
		"HdwpfwsfaldCWH0wtNEjQInXawQ0sHBIfKsrVufzvFc",
		"446baba98f29c496bc22586c20a89adee0dfcb069cc9d3d51854c8ab92d31ef4",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"init")
	if err != nil {
		t.Errorf("Insert into db error-r: %q", err)
	}

	// borked the JWT HMAC
	input := `{"challengeResponse":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImRpZDpqbGluYzpqWGp5N04zTkszTWJvWmpoQUdnWlBKUnFLcjEzVFB0ckxZMEJzejdDeWljIiwic2lnbmF0dXJlIjoiOTdqQkpGaDhSVzVUbDRPaXpDeWhPTDZKbHFwaHlYd01vNVFlZENzdmFiWFBJYWo5Tk1RWXZPRUQ2MFpkeTIxbnFvSlpZTFlSSlR2Tl9Rd3gxMGkyQWciLCJpYXQiOjE1NDMyODYxMTR9.5goPknYr6WNxSdnLpBnQWfeB438OnvXw-q-wR5cTWex"}`
	inputReader := strings.NewReader(input)

	didID := fmt.Sprintf("%s", `did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic`)
	supersedesID := fmt.Sprintf("%s", `did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI`)

	req, err := http.NewRequest("POST", "/confirmSupersede", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(confirmSupersede)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	expected := fmt.Sprintf(`{"success":"false", "error":"JWT-signature is invalid"}`)
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: want %s got %s", expected, rr.Body.String())
	}

	// check that the DB record is not marked verified
	var status, supersededBy string
	expected = "init"
	row := DB.QueryRow(fmt.Sprintf(`select status FROM didstore WHERE id = '%s'`, didID))
	err = row.Scan(&status)
	if status != expected {
		t.Errorf("database returned unexpected value: got %v want %v with error %v", status, expected, err)
	}

	// check that the supersedee DB record is correct
	expected = "verified"
	row = DB.QueryRow(fmt.Sprintf(`select status, superseded_by FROM didstore WHERE id = '%s'`, supersedesID))
	err = row.Scan(&status, &supersededBy)
	if status != expected || supersededBy != "" {
		t.Errorf("database returned unexpected value: got %v, %v want %v, %v with error %v", status, supersededBy, expected, "", err)
	}

	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()

}

func TestGoodSupersedeConfirm(t *testing.T) {
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

	// enter supersedee data in the DB
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
		t.Errorf("Insert into db error-e: %q", err)
	}
	// enter superseder data in the DB
	stmt, _ = DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              challenge,
                                              supersedes,
                                              status) VALUES ($1, $2, $3, $4, $5, $6, $7)`)
	_, err = stmt.Exec("did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic",
		"HdwpfwsfaldCWH0wtNEjQInXawQ0sHBIfKsrVufzvFc",
		"446baba98f29c496bc22586c20a89adee0dfcb069cc9d3d51854c8ab92d31ef4",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"init")
	if err != nil {
		t.Errorf("Insert into db error-r: %q", err)
	}

	input := `{"challengeResponse":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImRpZDpqbGluYzpqWGp5N04zTkszTWJvWmpoQUdnWlBKUnFLcjEzVFB0ckxZMEJzejdDeWljIiwic2lnbmF0dXJlIjoiOTdqQkpGaDhSVzVUbDRPaXpDeWhPTDZKbHFwaHlYd01vNVFlZENzdmFiWFBJYWo5Tk1RWXZPRUQ2MFpkeTIxbnFvSlpZTFlSSlR2Tl9Rd3gxMGkyQWciLCJpYXQiOjE1NDMyODYxMTR9.5goPknYr6WNxSdnLpBnQWfeB438OnvXw-q-wR5cTWes"}`
	inputReader := strings.NewReader(input)

	didID := fmt.Sprintf("%s", `did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic`)
	supersedesID := fmt.Sprintf("%s", `did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI`)

	req, err := http.NewRequest("POST", "/confirmSupersede", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(confirmSupersede)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	expected := fmt.Sprintf(`{"success":"true", "id":%q}`, didID)
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: want %s got %s", expected, rr.Body.String())
	}

	var status, supersededBy string
	expectedStatus := "verified"
	// check that the superseder DB record is now marked verified
	row := DB.QueryRow(fmt.Sprintf(`select status FROM didstore WHERE id = '%s'`, didID))
	err = row.Scan(&status)
	if status != expectedStatus {
		t.Errorf("database returned unexpected value: got %v want %v with error %v", status, expectedStatus, err)
	}

	// check that the supersedee DB record is correct
	expectedStatus = "superseded"

	row = DB.QueryRow(fmt.Sprintf(`select status, superseded_by FROM didstore WHERE id = '%s'`, supersedesID))
	err = row.Scan(&status, &supersededBy)
	if status != expectedStatus || supersededBy != didID {
		t.Errorf("database returned unexpected value: got %v, %v want %v, %v with error %v", status, supersededBy, expectedStatus, didID, err)
	}

	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()

}
