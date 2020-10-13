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
contextV1 = "https://w3id.org/did/v1"
contextV2 = "https://www.w3.org/ns/did/v1"

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
```

#### Run the migrations

```sh
./migrations/migrate -path migrations/ -url postgres://localhost/did?sslmode=disable up
```

### Creating a key pair

```

```

### Starting the server

On Mac OS X:
```sh
dist/mac/didserver
```
