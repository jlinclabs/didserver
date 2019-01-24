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

func TestNoAgentRegisterInput(t *testing.T) {
	input := strings.NewReader("")

	req, err := http.NewRequest("POST", "/agentRegister", input)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(agentRegister)

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

func TestAgentRegisterBadJWTSignature(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}

	input := strings.NewReader(`{"agentkey":"74fb5cf4f8ce852e143e2859d61b7df5c6572edbbb580e71395d3266506face7","registration":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJ7XCJAY29udGV4dFwiOlwiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjFcIixcImlkXCI6XCJkaWQ6amxpbmM6TjU0ejEzZGtySTU2RU95SWR5TVpsRzhyMmVGZ1lZb3VWVDNIMFByWDQ5MFwiLFwiY3JlYXRlZFwiOlwiMjAxOS0wMS0xOVQyMTo1OToyNC4zMDlaXCIsXCJwdWJsaWNLZXlcIjpbe1wiaWRcIjpcImRpZDpqbGluYzpONTR6MTNka3JJNTZFT3lJZHlNWmxHOHIyZUZnWVlvdVZUM0gwUHJYNDkwI3NpZ25pbmdcIixcInR5cGVcIjpcImVkMjU1MTlcIixcIm93bmVyXCI6XCJkaWQ6amxpbmM6TjU0ejEzZGtySTU2RU95SWR5TVpsRzhyMmVGZ1lZb3VWVDNIMFByWDQ5MFwiLFwicHVibGljS2V5QmFzZTY0XCI6XCJONTR6MTNka3JJNTZFT3lJZHlNWmxHOHIyZUZnWVlvdVZUM0gwUHJYNDkwXCJ9LHtcImlkXCI6XCJkaWQ6amxpbmM6TjU0ejEzZGtySTU2RU95SWR5TVpsRzhyMmVGZ1lZb3VWVDNIMFByWDQ5MCNlbmNyeXB0aW5nXCIsXCJ0eXBlXCI6XCJjdXJ2ZTI1NTE5XCIsXCJvd25lclwiOlwiZGlkOmpsaW5jOk41NHoxM2Rrckk1NkVPeUlkeU1abEc4cjJlRmdZWW91VlQzSDBQclg0OTBcIixcInB1YmxpY0tleUJhc2U2NFwiOlwid0R1S2lQQzAyWGJJYjZkdHBqVFR5YkR4ZTNxc1FzdkFDcnhzYzN5UGoyMFwifV19Iiwic2lnbmF0dXJlIjoiSUNwTUlhTGFKa1N5ckU4YmpBU0huNERhejZIQmNIcVc1OGNTUkNuQzJqdENqT01mMlJMU0d1Z01EaU84WjNzeDhfVlhvQ01XRGRRWnhzMDZiMWhWQXciLCJzZWNyZXQiOnsiY3lwaGVydGV4dCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQU9takNpejhUZDhoX1ZPbFVPZjRKdHFoU2x6WnNSV1dwaGZHNXNVRmNKbHpUeE1TMV92Z3lmNmtNN0xQUlF2OGtLVkptOUVqLThFc0ROVTRuYU5wdjM1MUM3UVNqZmpNTXBUd2UxR2RIVG5BIiwibm9uY2UiOiJ0R2pNRWstZmh4UF9kQ3Brb2RWbUUwNE9zSEwxZUhfcSJ9LCJpYXQiOjE1NDc5MzUxNjR9.n8rOyusQjRrKo0Pjv79SY0-nEn0gYR8Q7PdqjQFBVtU"}`)

	req, err := http.NewRequest("POST", "/agentRegister", input)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(agentRegister)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	expected := `{"success":"false", "error":"JWT-signature is invalid"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestUnknownAgentRegisterInput(t *testing.T) {
	if _, err := toml.DecodeFile("./test.config.toml", &Conf); err != nil {
		log.Fatal(err)
		return
	}

	input := strings.NewReader(`{"agentkey":"ab373311c9047728c1be7137b51c513bea97fc5764411becc7c0a7ec1c7053ea","registration":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJ7XCJAY29udGV4dFwiOlwiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjFcIixcImlkXCI6XCJkaWQ6amxpbmM6TjU0ejEzZGtySTU2RU95SWR5TVpsRzhyMmVGZ1lZb3VWVDNIMFByWDQ5MFwiLFwiY3JlYXRlZFwiOlwiMjAxOS0wMS0xOVQyMTo1OToyNC4zMDlaXCIsXCJwdWJsaWNLZXlcIjpbe1wiaWRcIjpcImRpZDpqbGluYzpONTR6MTNka3JJNTZFT3lJZHlNWmxHOHIyZUZnWVlvdVZUM0gwUHJYNDkwI3NpZ25pbmdcIixcInR5cGVcIjpcImVkMjU1MTlcIixcIm93bmVyXCI6XCJkaWQ6amxpbmM6TjU0ejEzZGtySTU2RU95SWR5TVpsRzhyMmVGZ1lZb3VWVDNIMFByWDQ5MFwiLFwicHVibGljS2V5QmFzZTY0XCI6XCJONTR6MTNka3JJNTZFT3lJZHlNWmxHOHIyZUZnWVlvdVZUM0gwUHJYNDkwXCJ9LHtcImlkXCI6XCJkaWQ6amxpbmM6TjU0ejEzZGtySTU2RU95SWR5TVpsRzhyMmVGZ1lZb3VWVDNIMFByWDQ5MCNlbmNyeXB0aW5nXCIsXCJ0eXBlXCI6XCJjdXJ2ZTI1NTE5XCIsXCJvd25lclwiOlwiZGlkOmpsaW5jOk41NHoxM2Rrckk1NkVPeUlkeU1abEc4cjJlRmdZWW91VlQzSDBQclg0OTBcIixcInB1YmxpY0tleUJhc2U2NFwiOlwid0R1S2lQQzAyWGJJYjZkdHBqVFR5YkR4ZTNxc1FzdkFDcnhzYzN5UGoyMFwifV19Iiwic2lnbmF0dXJlIjoiSUNwTUlhTGFKa1N5ckU4YmpBU0huNERhejZIQmNIcVc1OGNTUkNuQzJqdENqT01mMlJMU0d1Z01EaU84WjNzeDhfVlhvQ01XRGRRWnhzMDZiMWhWQXciLCJzZWNyZXQiOnsiY3lwaGVydGV4dCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQU9takNpejhUZDhoX1ZPbFVPZjRKdHFoU2x6WnNSV1dwaGZHNXNVRmNKbHpUeE1TMV92Z3lmNmtNN0xQUlF2OGtLVkptOUVqLThFc0ROVTRuYU5wdjM1MUM3UVNqZmpNTXBUd2UxR2RIVG5BIiwibm9uY2UiOiJ0R2pNRWstZmh4UF9kQ3Brb2RWbUUwNE9zSEwxZUhfcSJ9LCJpYXQiOjE1NDc5MzUxNjR9.n8rOyusQjRrKo0Pjv79SY2-nEn0gYR8Q7PdqjQFBVtU"}`)

	req, err := http.NewRequest("POST", "/agentRegister", input)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(agentRegister)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	expected := `{"success":"false", "error":"JWT-agentkey not found"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestGoodAgentRegisterInput(t *testing.T) {
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

	input := `{"agentkey":"74fb5cf4f8ce852e143e2859d61b7df5c6572edbbb580e71395d3266506face7","registration":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJ7XCJAY29udGV4dFwiOlwiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjFcIixcImlkXCI6XCJkaWQ6amxpbmM6eUJUV2c3UjBZUTlYa1R1XzAtcGVPMlVTZ2pGZ1lwTVRTRDJBbFVZU1RISVwiLFwiY3JlYXRlZFwiOlwiMjAxOS0wMS0xOVQyMToxNDo1Mi4zNjRaXCIsXCJwdWJsaWNLZXlcIjpbe1wiaWRcIjpcImRpZDpqbGluYzp5QlRXZzdSMFlROVhrVHVfMC1wZU8yVVNnakZnWXBNVFNEMkFsVVlTVEhJI3NpZ25pbmdcIixcInR5cGVcIjpcImVkMjU1MTlcIixcIm93bmVyXCI6XCJkaWQ6amxpbmM6eUJUV2c3UjBZUTlYa1R1XzAtcGVPMlVTZ2pGZ1lwTVRTRDJBbFVZU1RISVwiLFwicHVibGljS2V5QmFzZTY0XCI6XCJ5QlRXZzdSMFlROVhrVHVfMC1wZU8yVVNnakZnWXBNVFNEMkFsVVlTVEhJXCJ9LHtcImlkXCI6XCJkaWQ6amxpbmM6eUJUV2c3UjBZUTlYa1R1XzAtcGVPMlVTZ2pGZ1lwTVRTRDJBbFVZU1RISSNlbmNyeXB0aW5nXCIsXCJ0eXBlXCI6XCJjdXJ2ZTI1NTE5XCIsXCJvd25lclwiOlwiZGlkOmpsaW5jOnlCVFdnN1IwWVE5WGtUdV8wLXBlTzJVU2dqRmdZcE1UU0QyQWxVWVNUSElcIixcInB1YmxpY0tleUJhc2U2NFwiOlwiMklRRHFjSElEUGl1cGpKTlNRS0FLQkpTYi1EM2VqWDVqcDQ1VUlSRWJ6WVwifV19Iiwic2lnbmF0dXJlIjoia1JHQzk2c2Y2LUgwelhpQ3pWZVZYSjVpejB0bDFxMmtIQUJXTHM3QnJYQTFjNTNFbEprQXpjU2JvNEFyUEZObzVtRE8zMGM2SUx2QXpvQzM0MFRPQlEiLCJzZWNyZXQiOnsiY3lwaGVydGV4dCI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQVBjQkEwdW50RkZuQXZYUUdibjViN25XUXM1cHRoTmtKV1loZ2VLSHM5WjFvSURlRHYwSHhTTGVDZ21hUEdkc0xWNGd2RmdvNTdCTDBtOUZmc0pFcUh5MHBqS0dTZTdPMWlVNXo3Zkw1YTI5Iiwibm9uY2UiOiJ2SmVCdFdtS3FIMW9RYWdpYThfbVVhQko1MzZiTDBPWSJ9LCJpYXQiOjE1NDc5MzI0OTJ9.Q6iDdJz8d4KZP74DMlwIOCVTzABX_w5doC0A_xHjqt0"}`
	inputReader := strings.NewReader(input)

	req, err := http.NewRequest("POST", "/agentRegister", inputReader)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(agentRegister)

	handler.ServeHTTP(rr, req)

	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v", ctype, "application/json")
	}

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	goodBody := regexp.MustCompile(`^\{"success":"true", "id":"did:jlinc:[\w\-]+"\}$`)
	if !goodBody.MatchString(rr.Body.String()) {
		t.Errorf("handler returned unexpected body: got %v", rr.Body.String())
	}

	var id, root, did, status string
	expectedID := "did:jlinc:yBTWg7R0YQ9XkTu_0-peO2USgjFgYpMTSD2AlUYSTHI"
	expectedRoot := "did:jlinc:yBTWg7R0YQ9XkTu_0-peO2USgjFgYpMTSD2AlUYSTHI"
	expectedStatus := "verified"

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
	stmt, err := DB.Prepare("DELETE FROM didstore")
	if err != nil {
		log.Fatal(err)
		return
	}
	stmt.Exec("verified")
}
