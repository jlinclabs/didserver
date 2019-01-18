package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/go-chi/chi"
)

func TestSupersededRevoked(t *testing.T) {
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

	stmt, err := DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              did,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              status,
                                              supersedes,
                                              modified) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = stmt.Exec("did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"{\"did\":{\"@context\":\"https://w3id.org/did/v1\",\"created\":\"2018-11-25T21:51:16.366Z\",\"id\":\"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic\",\"publicKey\":[{\"id\":\"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#signing\",\"owner\":\"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic\",\"publicKeyBase64\":\"jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic\",\"type\":\"ed25519\"},{\"id\":\"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic#encrypting\",\"owner\":\"did:jlinc:jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic\",\"publicKeyBase64\":\"HdwpfwsfaldCWH0wtNEjQInXawQ0sHBIfKsrVufzvFc\",\"type\":\"curve25519\"}]}}",
		"jXjy7N3NK3MboZjhAGgZPJRqKr13TPtrLY0Bsz7Cyic",
		"HdwpfwsfaldCWH0wtNEjQInXawQ0sHBIfKsrVufzvFc",
		"revoked",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	stmt, _ = DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              did,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              challenge,
                                              status,
																							superseded_at,
                                              modified) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`)
	_, err = stmt.Exec("did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"{\"did\":{\"@context\":\"https://w3id.org/did/v1\",\"created\":\"2018-11-25T21:26:43.550Z\",\"id\":\"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI\",\"publicKey\":[{\"id\":\"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI#signing\",\"owner\":\"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI\",\"publicKeyBase64\":\"xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI\",\"type\":\"ed25519\"},{\"id\":\"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI#encrypting\",\"owner\":\"did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI\",\"publicKeyBase64\":\"Vk3kVIvGFV4Ew5m3xJ43N8T5WNFX7qjMOSrJ3Gu4m3E\",\"type\":\"curve25519\"}]}}",
		"xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI",
		"Vk3kVIvGFV4Ew5m3xJ43N8T5WNFX7qjMOSrJ3Gu4m3E",
		"446baba98f29c496bc22586c20a89adee0dfcb069cc9d3d51854c8ab92d31ef4",
		"superseded",
		"2018-11-27 04:01:54.893276+00:00")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	stmt, _ = DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              did,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              status,
                                              modified) VALUES ($1, $2, $3, $4, $5, $6, NOW())`)
	_, err = stmt.Exec("did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc",
		"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc",
		"{\"did\":{\"@context\":\"https://w3id.org/did/v1\",\"created\":\"2018-12-15T06:36:08.964Z\",\"id\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"publicKey\":[{\"id\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc#signing\",\"owner\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"publicKeyBase64\":\"r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"type\":\"ed25519\"},{\"id\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc#encrypting\",\"owner\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"publicKeyBase64\":\"cQ-4NprnnXyilGUpFLvd6rB2jhuafAFZ0Y4sX_twsQs\",\"type\":\"curve25519\"}]}}",
		"r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc",
		"cQ-4NprnnXyilGUpFLvd6rB2jhuafAFZ0Y4sX_twsQs",
		"init")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	stmt, _ = DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              did,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              status,
                                              modified) VALUES ($1, $2, $3, $4, $5, $6, NOW())`)
	_, err = stmt.Exec("did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0",
		"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0",
		"{\"did\":{\"@context\":\"https://w3id.org/did/v1\",\"created\":\"2018-12-15T06:35:37.541Z\",\"id\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"publicKey\":[{\"id\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0#signing\",\"owner\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"publicKeyBase64\":\"qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"type\":\"ed25519\"},{\"id\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0#encrypting\",\"owner\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"publicKeyBase64\":\"roTYdoOre30Gx2Z9GVfqZ9KsiG3rIPPAf8mztg5uVlE\",\"type\":\"curve25519\"}]}}",
		"qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0",
		"roTYdoOre30Gx2Z9GVfqZ9KsiG3rIPPAf8mztg5uVlE",
		"verified")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	req, err := http.NewRequest("GET", "/history", nil)
	if err != nil {
		t.Fatal(err)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("DID", "did:jlinc:xsavxziATze7ycvEqFJuWp7u7J2M_AUWiQcRFs8EAZI")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(history)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	type HistoryResult struct { //container to be converted into the final JSON result
		DID        interface{} `json:"did"`
		Valid      string      `json:"valid,omitempty"`
		Superseded string      `json:"superseded,omitempty"`
		Revoked    string      `json:"revoked,omitempty"`
	}

	type ExpectedHistory struct {
		History []HistoryResult `json:"history"`
	}
	var expectedHistory ExpectedHistory
	json.Unmarshal([]byte(rr.Body.String()), &expectedHistory)

	if len(expectedHistory.History) != 2 {
		t.Errorf("got %d history items want %d", len(expectedHistory.History), 2)
	}
	RFC3339Rxp := regexp.MustCompile(`^[\d]{4}\-[\d]{2}\-[\d]{2}T[\d]{2}\:[\d]{2}\:[\d]{2}Z$`)
	if !RFC3339Rxp.MatchString(expectedHistory.History[0].Revoked) {
		t.Errorf("incorrect Revoked date: got %v", expectedHistory.History[0].Revoked)
	}
	if !RFC3339Rxp.MatchString(expectedHistory.History[1].Superseded) {
		t.Errorf("incorrect Superseded date: got %v", expectedHistory.History[1].Superseded)
	}

	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()

}

func TestVerified(t *testing.T) {
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

	stmt, err := DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              did,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              status,
                                              modified) VALUES ($1, $2, $3, $4, $5, $6, NOW())`)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = stmt.Exec("did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0",
		"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0",
		"{\"did\":{\"@context\":\"https://w3id.org/did/v1\",\"created\":\"2018-12-15T06:35:37.541Z\",\"id\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"publicKey\":[{\"id\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0#signing\",\"owner\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"publicKeyBase64\":\"qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"type\":\"ed25519\"},{\"id\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0#encrypting\",\"owner\":\"did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0\",\"publicKeyBase64\":\"roTYdoOre30Gx2Z9GVfqZ9KsiG3rIPPAf8mztg5uVlE\",\"type\":\"curve25519\"}]}}",
		"qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0",
		"roTYdoOre30Gx2Z9GVfqZ9KsiG3rIPPAf8mztg5uVlE",
		"verified")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	req, err := http.NewRequest("GET", "/history", nil)
	if err != nil {
		t.Fatal(err)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("DID", "did:jlinc:qPziBWwc8Y2e7LV5-hj92GYJ4rgyhXdALlXc43b9uW0")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(history)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	type HistoryResult struct { //container to be converted into the final JSON result
		DID        interface{} `json:"did"`
		Valid      string      `json:"valid,omitempty"`
		Superseded string      `json:"superseded,omitempty"`
		Revoked    string      `json:"revoked,omitempty"`
	}

	type ExpectedHistory struct {
		History []HistoryResult `json:"history"`
	}
	var expectedHistory ExpectedHistory
	json.Unmarshal([]byte(rr.Body.String()), &expectedHistory)

	if len(expectedHistory.History) != 1 {
		t.Errorf("got %d history items want %d", len(expectedHistory.History), 1)
	}
	RFC3339Rxp := regexp.MustCompile(`^[\d]{4}\-[\d]{2}\-[\d]{2}T[\d]{2}\:[\d]{2}\:[\d]{2}Z$`)
	if !RFC3339Rxp.MatchString(expectedHistory.History[0].Valid) {
		t.Errorf("incorrect Valid date: got %v", expectedHistory.History[0].Valid)
	}

	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()

}

func TestInitNotVerified(t *testing.T) {
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

	stmt, err := DB.Prepare(`INSERT INTO didstore (id,
                                              root,
                                              did,
                                              signing_pubkey,
                                              encrypting_pubkey,
                                              status,
                                              modified) VALUES ($1, $2, $3, $4, $5, $6, NOW())`)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = stmt.Exec("did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc",
		"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc",
		"{\"did\":{\"@context\":\"https://w3id.org/did/v1\",\"created\":\"2018-12-15T06:36:08.964Z\",\"id\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"publicKey\":[{\"id\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc#signing\",\"owner\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"publicKeyBase64\":\"r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"type\":\"ed25519\"},{\"id\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc#encrypting\",\"owner\":\"did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc\",\"publicKeyBase64\":\"cQ-4NprnnXyilGUpFLvd6rB2jhuafAFZ0Y4sX_twsQs\",\"type\":\"curve25519\"}]}}",
		"r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc",
		"cQ-4NprnnXyilGUpFLvd6rB2jhuafAFZ0Y4sX_twsQs",
		"init")
	if err != nil {
		t.Errorf("Insert into db error: %q", err)
	}

	req, err := http.NewRequest("GET", "/history", nil)
	if err != nil {
		t.Fatal(err)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("DID", "did:jlinc:r1l6hFO3O4q7B16xmTHRfuSiQIg3nx_i-EfGQAwRwzc")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(history)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNotFound)
	}

	type ExpectedStatus struct {
		Status string `json:"status"`
	}
	var expectedStatus ExpectedStatus
	json.Unmarshal([]byte(rr.Body.String()), &expectedStatus)

	if expectedStatus.Status != "not found" {
		t.Errorf("handler returned wrong result status: got %v want %v", expectedStatus.Status, "not found")
	}

	stmt, _ = DB.Prepare("DELETE FROM didstore")
	stmt.Exec()

}
