# DID Server

A digital identity server.

## Development


### Setup
Install postgresql 9.6 or higher.

On Mac OS X:
```sh
brew install postgresql@9.6
```

### Make your `config.toml`


```toml
[database]
connection_string = "postgres://localhost:5432/did?sslmode=disable"

[keys]
public = "GET THIS KEY IN THE NEXT STEP"
secret = "GET THIS KEY IN THE NEXT STEP"

[at]
context = "https://w3id.org/did/v1"

[app]
url = "http://localhost:5001"
port = ":5001"

[api_auth] # apiKey = apiSecret -- these are test values:
"74fb5cf4f8ce852e143e2859d61b7df5c6572edbbb580e71395d3266506face7" = "809d311ff23626ddf58297f3322f84ec2b0cedf1b2a38b3d456b39298db61820"

```

### Generate keys

```
cd jlinc-did-client
npm i
node
node> require('./jlinc-did/createEntity.js')()
copy // encryptingPublicKey and encryptingPrivateKey
```

### Starting the SQL Commandline

```sh
psql postgres
```

#### Manually initialize the database

```sql
CREATE database did;
\c did

CREATE TABLE IF NOT EXISTS didstore (
  id text PRIMARY KEY,
  root text DEFAULT '',
  did text DEFAULT '',
  signing_pubkey text DEFAULT '',
  encrypting_pubkey text DEFAULT '',
  secret_cypher text DEFAULT '',
  secret_nonce text DEFAULT '',
  secret_master text DEFAULT '',
  challenge text DEFAULT '',
  status text DEFAULT 'init',
  agent_id text DEFAULT '',
  supersedes text DEFAULT '',
  superseded_by text DEFAULT '',
  superseded_at timestamp,
  created timestamp DEFAULT current_timestamp,
  modified timestamp
);
CREATE INDEX ON didstore (root);
CREATE INDEX ON didstore (superseded_by);
```

### Creating a key pair

```

```

### Starting the server

On Mac OS X:
```sh
dist/mac/didserver
```
