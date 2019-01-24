package main

import (
	_ "github.com/lib/pq"
)

func recordDID(d *Registration) error {
	stmt, err := DB.Prepare(`INSERT INTO didstore(
    id,
    root,
    did,
    signing_pubkey,
    encrypting_pubkey,
    secret_cypher,
    secret_nonce,
    secret_master,
    challenge,
    status,
		agent_id,
		supersedes,
    superseded_by) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(
		d.DID.ID,
		d.Root,
		d.Raw,
		d.SigningKey,
		d.EncryptingKey,
		d.Secret.Cyphertext,
		d.Secret.Nonce,
		d.Secret.MasterKey,
		d.Challenge,
		d.Status,
		d.AgentID,
		d.Supersedes,
		d.SupersededBy)
	if err != nil {
		return err
	}

	return nil
}
