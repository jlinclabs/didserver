# DID Server

A digitial identity server.

## Development


### Setup
Install cockroach.

On Mac OS X:
```sh
brew install cockroach
```

### Make your `config.toml`


```toml
[database]
connection_string = "postgres://root@localhost:26257/did?sslmode=disable"

[keys]
public = "GET THIS KEY IN THE NEXT STEP"
secret = "GET THIS KEY IN THE NEXT STEP"

[at]
context = "https://w3id.org/did/v1"

[app]
url = "http://localhost:5001"
port = ":5001"
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
cockroach sql --insecure
```

#### Manually initialize the database

```sql
CREATE database did;
SET database = did;

CREATE TABLE didstore (
  id STRING PRIMARY KEY,
  root STRING DEFAULT '',
  did STRING DEFAULT '',
  signing_pubkey STRING DEFAULT '',
  encrypting_pubkey STRING DEFAULT '',
  secret_cypher STRING DEFAULT '',
  secret_nonce STRING DEFAULT '',
  secret_master STRING DEFAULT '',
  challenge STRING DEFAULT '',
  status STRING DEFAULT 'init',
  supersedes STRING DEFAULT '',
  superseded_by STRING DEFAULT '',
  superseded_at TIMESTAMP,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  modified TIMESTAMP,
  INDEX (root),
  INDEX (superseded_by)
);
```

### Creating a key pair

```

```

### Starting the server

On Mac OS X:
```sh
dist/mac/didserver
```
