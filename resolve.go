package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	_ "github.com/lib/pq"
)

func resolve(w http.ResponseWriter, r *http.Request) {
	DIDstr := chi.URLParam(r, "DID")
	if _, ok := getValidID(DIDstr); !ok {
		w.Header().Set("Content-Type", "application/ld+json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"cannot parse request"}`))
		return
	}

	stmt, err := DB.Prepare("SELECT did, status FROM didstore WHERE id = $1")
	defer stmt.Close()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-st"`)
		return
	}
	var did, status string
	err = stmt.QueryRow(DIDstr).Scan(&did, &status)
	switch {
	case err == sql.ErrNoRows: //didn't find it
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"status":"not found"}`))
	case err != nil: // query error!
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-q"`)
	case status == "revoked":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		w.Write([]byte(`{"status":"revoked"}`))
	case status == "superseded":
		superID, superURL := getSupersededBy(DIDstr)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", superURL)
		w.WriteHeader(http.StatusSeeOther)
		fmt.Fprintf(w, `{"supersededBy":%q`, superID)
	case status == "verified": //success
		w.Header().Set("Content-Type", "application/ld+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(did))
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"status":"not found"}`))
	}
}

func getSupersededBy(DIDstr string) (id, url string) {
	return "not implemented", "http://example.com"
}
