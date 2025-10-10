# incognito-light-registrator

## Description

This service is responsible for verifying a user-provided ZKP and real-world identity certificate

## Endpoints

### create_identity

`register` verifies a user-provided ZKP that proves the real-world identity ownership, validates this real-world 
identity certificate and return poseidon hash of truncated signed attributes by 252 bits along with ECDSA signature of
dg1 and poseidon hash.
Path: `POST /integrations/incognito-light-registrator/v1/register`<br>
Payload example (proof is provided as an example and actually does not prove anything):
```json
{
  "data": {
    "attributes": {
      "document_sod": {
        "hash_algorithm": "SHA256",
        "signature_algorithm": "ECDSA",
        "signed_attributes": "0x303030303030303030303030303030303030303030303030303030303030",
        "encapsulated_content": "0x303030303030303030303030303030303030303030303030303030303030",
        "signature": "0x303030303030303030303030303030303030303030303030303030303030",
        "aa_signature": "0x303030303030303030303030303030303030303030303030303030303030",
        "pem_file": "-----BEGIN CERTIFICATE-----\nbase64_pem...\n-----END CERTIFICATE-----",
        "dg15": "No dg15 sorry :D"
      },
      "zk_proof": {
        "pub_signals": [
          "303030303030303030303030303030303030303030303030303030303030",
          "303030303030303030303030303030303030303030303030303030303030",
          "303030303030303030303030303030303030303030303030303030303030"
        ],
        "proof": {
          "pi_a": [
            "303030303030303030303030303030303030303030303030303030303030",
            "303030303030303030303030303030303030303030303030303030303030",
            "1"
          ],
          "protocol": "groth16",
          "pi_c": [
            "303030303030303030303030303030303030303030303030303030303030",
            "303030303030303030303030303030303030303030303030303030303030",
            "1"
          ],
          "pi_b": [
            [
              "303030303030303030303030303030303030303030303030303030303030",
              "303030303030303030303030303030303030303030303030303030303030"
            ],
            [
              "303030303030303030303030303030303030303030303030303030303030",
              "303030303030303030303030303030303030303030303030303030303030"
            ],
            [
              "1",
              "0"
            ]
          ]
        }
      }
    }
  }
}
```

## Install

  ```
  git clone github.com/rarimo/incognito-light-registrator
  cd incognito-light-registrator
  go run main.go  migrate up && go run service
  export KV_VIPER_FILE=./config.yaml
  ./main migrate up
  ./main run service
  ```

## Documentation

We do use openapi:json standard for API. We use swagger for documenting our API.

To open online documentation, go to [swagger editor](http://localhost:8080/swagger-editor/) here is how you can start it
```
  cd docs
  npm install
  npm start
```
To build documentation use `npm run build` command,
that will create open-api documentation in `web_deploy` folder.

To generate resources for Go models run `./generate.sh` script in root folder.
use `./generate.sh --help` to see all available options.

Note: if you are using Gitlab for building project `docs/spec/paths` folder must not be
empty, otherwise only `Build and Publish` job will be passed.  

## Running from docker 
  
Make sure that docker installed.

use `docker run ` with `-p 8080:80` to expose port 80 to 8080

  ```
  docker build -t github.com/rarimo/incognito-light-registrator .
  docker run -e KV_VIPER_FILE=/config.yaml github.com/rarimo/incognito-light-registrator
  ```

## Running from Source

* Set up environment value with config file path `KV_VIPER_FILE=./config.yaml`
* Provide valid config file
* Launch the service with `migrate up` command to create database schema
* Launch the service with `run service` command


### Database
For services, we do use ***PostgresSQL*** database. 
You can [install it locally](https://www.postgresql.org/download/) or use [docker image](https://hub.docker.com/_/postgres/).


### Third-party services


## Contact

Responsible
The primary contact for this project is  [//]: # (TODO: place link to your telegram and email)
