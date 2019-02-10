package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/lib/pq"
)

/**********************
TODO:  on error, send to job queue for retry later
***********************/

func addChainlink(id string, did string) error {
	type QueryResult struct {
		id  string
		DID string
	}

	var ctx = context.TODO() //empty context

	tx, err := DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		logChainlinkError(fmt.Sprintf("%s : %s\n", id, err.Error()))
		return err
	}

	var chainlink string
	err = tx.QueryRow("SELECT chainlink FROM chainlinks ORDER BY seq DESC LIMIT 1").Scan(&chainlink)
	if err != nil && err != sql.ErrNoRows { //first run may return no rows
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logChainlinkError(fmt.Sprintf("%s : %s", id, rollbackErr.Error()))
			return fmt.Errorf("chainlinks error and could not roll back: %v %v", err, rollbackErr)
		}
		logChainlinkError(fmt.Sprintf("%s : %s", id, err.Error()))
		return fmt.Errorf("chainlinks error: %v", err)
	}

	didHash := getHash(did)
	chainHash := b64Decode(chainlink)
	chainHash = append(chainHash, didHash...)
	chain := getByteHash(chainHash)
	_, err = tx.Exec("INSERT INTO chainlinks (id, chainlink) VALUES ($1, $2)", id, b64Encode(chain))
	if err, ok := err.(*pq.Error); ok {
		if err.Code == "40001" {
			logChainlinkError(fmt.Sprintf("%s : %s", id, "chainlinks serialization error"))
			return fmt.Errorf("chainlinks serialization error")
		}
		logChainlinkError(fmt.Sprintf("%s : %s", id, err.Message))
		return fmt.Errorf("chainlinks transaction error: %v", err.Message)
	}

	err = tx.Commit()
	if err != nil {
		logChainlinkError(fmt.Sprintf("%s : %s", id, err.Error()))
		return fmt.Errorf("chainlinks transaction commit error: %v", err)
	}

	return nil
}

func logChainlinkError(s string) {
	f, _ := os.OpenFile("./log/chainlink.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintf("%s\n", s))
}
