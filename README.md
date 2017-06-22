# Updater
Securely handles automated software updates.

The Updater validates and obtains installation packages using [TUF](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) and  [Notary](https://github.com/docker/notary). Note that there are some minor differences
between Notary and TUFF so if the version of Notary is changed, this package will
need to be tested against the new version. The updater supports ECDSA
to verify signatures.  This option must be defined in the [Notary Server Configuration](https://github.com/docker/notary/blob/master/docs/reference/server-config.md).

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
