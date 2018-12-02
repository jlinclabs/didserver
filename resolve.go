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

	stmt, err := DB.Prepare("SELECT did, status, root FROM didstore WHERE id = $1")
	defer stmt.Close()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-st"`)
		return
	}
	var did, status, root string
	err = stmt.QueryRow(DIDstr).Scan(&did, &status, &root)
	switch {
	case err == sql.ErrNoRows: //didn't find it
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"status":"not found"}`))
	case err != nil: // query error!
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-q}"`)
	case status == "revoked":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		w.Write([]byte(`{"status":"revoked"}`))
	case status == "superseded":
		superID, superURL := getSupersededBy(root)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", superURL)
		w.WriteHeader(http.StatusSeeOther)
		fmt.Fprintf(w, `{"supersededBy":%q}`, superID)
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

func getSupersededBy(root string) (last, url string) {
	// use the root value to get the latest entry in the chain of DIDs with the same root
	stmt, _ := DB.Prepare("SELECT id FROM didstore WHERE root = $1 ORDER BY created DESC LIMIT 1")
	stmt.QueryRow(root).Scan(&last)
	return last, fmt.Sprintf(`%s/%s`, Conf.Root.URL, last)
}
