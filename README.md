# Updater
Securely handles automated software updates.

The Updater is designed to download and install software updates from a mirror. Updater ensures that downloaded files have not been altered or otherwise tampered with using [TUF](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) and  [Notary](https://github.com/docker/notary).

## How It Works

Updater uses a mirror such as Google Cloud Storage to store update targets, and uses
[Notary](https://github.com/docker/notary) to ensure targets have not been tampered
with.   

When the updater is invoked it performs actions as dictated in section 5.1 of the
[TUF Specification](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt).
When an application that uses Updater is released, it must be distributed with a
copy of the current TUF repo from the Notary server.  These
files are known as the local repository and are used to store state information about the local application
artifacts that are managed by Updater. After a successful update has occurred, the local TUF repository is synchronized with the remote
repository. Updater will periodically compare it's local repository with the remote
repository hosted by Notary.  When the Notary repository has changed an update
is trigged by the Updater, these updates either take the form of crypto key rotation
or local file updates. See the example application included with this package for
specific details for setting up an application to use updater.

## Notary Setup

Notary is comprised of server and client binaries. Notary sources and full documentation is [here](https://github.com/docker/notary).  Updater will use a Notary repository to detect and validate software updates. The Notary binaries can be built using the following commands:
```
git clone ssh://git@github.com/docker/notary
cd notary
make binaries
```
### Notary Server
 Notary server consists of three components, the Notary Signer, Server and a database.  Instructions on configuring and running these components can be found [here](https://github.com/docker/notary/blob/master/docs/running_a_service.md).  Updater supports ECDSA
 to verify signatures.  This option must be defined in the [Notary Server configuration](https://github.com/docker/notary/blob/master/docs/reference/server-config.md). Other than this requirement Notary Signer and Server may be configured for your particular environment.

 ```
 {
   "trust_service": {
     "key_algorithm": "ecdsa",
     "tls_ca_file": "./fixtures/root-ca.crt",
     "tls_client_cert": "./fixtures/notary-server.crt",
     "tls_client_key": "./fixtures/notary-server.key"
   }
 }
 ```
### Bootstrapping a Notary Repository

Updater requires a TUF repository to validate and detect software updates. Notary Client must be installed and **be in your search path** to create and manage the TUF repository used by Updater. Prebuilt versions Notary Client can be found [here](https://github.com/docker/notary/releases) or it can be built from source as previously described. Notary Client must be properly configured prior to use.  


### Development

Install dependencies.
```
make deps
```
Generate bindata.go which contains various artifacts needed for testing.
```
make generate
```
Test.
```
make test
```
