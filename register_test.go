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

func TestNoRegisterInput(t *testing.T) {
	input := strings.NewReader("")

	req, err := http.NewRequest("POST", "/register", input)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerDID)

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

func TestBadRegisterInput(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}

	Conf.IsTest = true //so it doesn't test the timestamp

	input := strings.NewReader(`{"did":{"@context":"https://w3id.org/did/v2","id":"did:jlincz:3Cza_sxboNZ_NajNVOrEH7YKPRQoD-PK7nq6nhgMy18","created":"2018-11-10T03:10:02.246Z","publicKey":[{"id":"did:jlinc:3Cza_sxboNZ_NajNVOrEH7YKPRQoD-PK7nq6nhgMy18#signing","type":"ed25519","owner":"did:jlinc:3Cza_sxboNZ_NajNVOrEH7YKPRQoD-PK7nq6nhgMy18","publicKeyBase64":"3Cza_sxboNZ_NajNVOrEH7YKPRQoD-PK7nq6nhgMy18"},{"id":"did:jlinc:3Cza_sxboNZ_NajNVOrEH7YKPRQoD-PK7nq6nhgMy18#encrypting","type":"curve25519","owner":"did:jlinc:3Cza_sxboNZ_NajNVOrEH7YKPRQoD-PK7nq6nhgMy18","publicKeyBase64":"GoRPEyMUoWGsPbWFcW7ivHsa-rzc91Kt279NEZrN4Fs"}]},"secret":{"cyphertext":"AAAAAAAAAAAAAAAAAAAAAAsECGk8sIPsxbHhkOMjmkakzTAbk-h8GaExILc2OJmn246Xj_NWYr6qGE95RLD_84VQOiWG_IEUc9hudnIhDbft5G8kxuKRDYlttfP5o95Z","nonce":"NEgURTnb869n60E7l6dUI5hw0S4Q4eaH"},"signature":"zznHMhSYRF_gCLVCnuA9ue1HMcC6g1jLf-vnO4wRlPW3c1FJKvXvTaFjo2BH_4wCyuDmstXNGk7A0xTXGPu1CQ"}`)

	req, err := http.NewRequest("POST", "/register", input)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerDID)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	expected := `{"success":false,"error":"request contained 6 errors: @context missing or incorrect, id must be did:jlinc:{base64 encoded string}, Signing key owner incorrect, Encrypting key owner incorrect, signature did not verify, secret did not decrypt correctly"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestGoodRegisterInput(t *testing.T) {
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

	input := `{"did":{"@context":"https://w3id.org/did/v1","id":"did:jlinc:UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8","created":"2018-11-10T03:06:56.933Z","publicKey":[{"id":"did:jlinc:UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8#signing","type":"ed25519","owner":"did:jlinc:UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8","publicKeyBase64":"UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8"},{"id":"did:jlinc:UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8#encrypting","type":"curve25519","owner":"did:jlinc:UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8","publicKeyBase64":"e7L_pkKOpbSiYPqOfUCnXMNRsrj0-iVqTu07SUlk3lg"}]},"secret":{"cyphertext":"AAAAAAAAAAAAAAAAAAAAADIP-Y7wyQT9qBD-bH7vyG9VUOWqcTgmqcfdvhc2ne1EMeRFKH0yT9qZJRdEpAEjZ9pn9_xvVMKyTFZbW9445QcH7rJ0ehciCnsvndFLSffw","nonce":"fLa-C4iSS4TNh136lsOdqoBMXoQS474Q"},"signature":"4u3q1zPI5I8mProAli2TwuELLc0gq1RI7AmvRQWK7rX_TTJhyJaOoeAS7AcKmAkIqfhh4yIbg7NT6stc1COHDA"}`
	inputReader := strings.NewReader(input)

	req, err := http.NewRequest("POST", "/register", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerDID)

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
	expectedID := "did:jlinc:UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8"
	expectedRoot := "did:jlinc:UrbERsLcleNbYyh1LvWWci45q-gxUE-wPqnQfGN7eF8"
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
	stmt, err := DB.Prepare("DELETE FROM didstore WHERE status = $1")
	if err != nil {
		log.Fatal(err)
		return
	}
	stmt.Exec("init")
}

func TestExtendedRegisterInput(t *testing.T) {
	// putting in another publicKey type into the array and adding a serviceEndpoint definition
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

	input := `{"did":{"@context":"https://w3id.org/did/v1","id":"did:jlinc:XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk","created":"2018-11-10T22:12:46.908Z","publicKey":[{"id":"did:jlinc:XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk#signing","type":"ed25519","owner":"did:jlinc:XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk","publicKeyBase64":"XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk"},{"id":"did:jlinc:XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk#encrypting","type":"curve25519","owner":"did:jlinc:XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk","publicKeyBase64":"jA9WMRFEyi_Q8iGoSSeWv399QDOrzVES4F3z5ph3cmQ"},{"id":"someid#whatever","type":"RsaSignatureAuthentication2018","owner":"whoknows","publicKeyPem":"-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\\r\\n"}],"service":[{"type":"ExampleService","serviceEndpoint":"https://example.com/endpoint/8377464"}]},"secret":{"cyphertext":"AAAAAAAAAAAAAAAAAAAAAGE1hwDQgInzzXHVBE6eVGP4xTm7fC0WnYy8lN7hrFkRrOVxh_880dWegu00FEJfjlTAgOizgQ14f_UmmEhkFYjdD9Qw3j7IV0zV74s5rlAm","nonce":"C91KbaLUWNy0N5hVrAroA9Xn1dFQI6Iv"},"signature":"O9vqGpnWOdb4JgnvILxURyKr2KZch2BSJ7FPAub9poxojEidfcG3gbLuoBVNX9hfPx9_hqIftT_BvEwQEZKwDw"}`
	inputReader := strings.NewReader(input)

	req, err := http.NewRequest("POST", "/register", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(registerDID)

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
	expectedID := "did:jlinc:XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk"
	expectedRoot := "did:jlinc:XzZ2-5f9o_lVXngwvUSN540ucbUeiyRWiHoMqZvTfpk"
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
	stmt, err := DB.Prepare("DELETE FROM didstore WHERE status = $1")
	if err != nil {
		log.Fatal(err)
		return
	}
	stmt.Exec("init")
}
