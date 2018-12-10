# DID Server

A digitial identity server.

## Development


### Setup
Install cockrach.

On Mac OS X:
```sh
brew install cockroach
```

### Make your `config.yoml`


```toml
[database]
connection_string = "postgres://localhost/did"

[keys]
public = "aPublicKey"
secret = "aSecretKey"

[at]
context = "https://w3id.org/did/v1"

[root]
url = "http://localhost:5001"
```

### Creating your server keys

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
