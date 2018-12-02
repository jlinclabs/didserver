package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/lib/pq"
)

func history(w http.ResponseWriter, r *http.Request) {
	DIDstr := chi.URLParam(r, "DID")
	if _, ok := getValidID(DIDstr); !ok {
		w.Header().Set("Content-Type", "application/ld+json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"cannot parse request"}`))
		return
	}

	type DidInstance struct {
		DID        string
		Status     string
		Created    time.Time
		Superseded pq.NullTime
		Modified   pq.NullTime
	}
	var instances []DidInstance

	stmt, err := DB.Prepare("SELECT r.did, r.status, r.superseded_at, r.created, r.modified FROM didstore AS s JOIN didstore AS r ON s.root = r.root WHERE s.id = $1 AND r.status != 'init' ORDER BY r.created ASC")
	defer stmt.Close()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"success":"false", "error":"database error-st"`)
		return
	}
	rows, _ := stmt.Query(DIDstr)
	defer rows.Close()
	i := 0
	for rows.Next() {
		i++
		var didInstance DidInstance
		if err = rows.Scan(&didInstance.DID, &didInstance.Status, &didInstance.Superseded, &didInstance.Created, &didInstance.Modified); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"success":"false", "error":"database error-rs"`)
			return
		}
		instances = append(instances, didInstance)
	}
	if i == 0 { //no rows
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"status":"not found"}`))
		return
	}

	type HistoryResult struct { //container to be converted into the final JSON result
		DID        interface{} `json:"did"`
		Valid      string      `json:"valid,omitempty"`
		Superseded string      `json:"superseded,omitempty"`
		Revoked    string      `json:"revoked,omitempty"`
	}
	var results []HistoryResult
	type RawDid struct { //container for the DID object
		DID interface{} `json:"did"`
	}

	for _, instance := range instances {
		var historyResult HistoryResult
		var raw RawDid
		//get the DID object into the HistoryResult struct field
		json.Unmarshal([]byte(instance.DID), &raw)
		historyResult.DID = raw.DID

		switch instance.Status {
		case "valid":
			historyResult.Valid = instance.Created.Format(time.RFC3339)
		case "superseded":
			if instance.Superseded.Valid {
				historyResult.Superseded = instance.Superseded.Time.Format(time.RFC3339)
			}
		case "revoked":
			if instance.Modified.Valid {
				historyResult.Revoked = instance.Modified.Time.Format(time.RFC3339)
			}
		}

		results = append(results, historyResult)
	}

	jsn, _ := json.Marshal(results)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"history":%s}`, jsn)
}
