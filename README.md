# updater
Securely handles automated software updates.

The updater validates and obtains installation packages using [TUF](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) and  [Notary](https://github.com/docker/notary). Not that there are some minor differences
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

Updater uses Google Cloud Storage to store update targets, and uses
[Notary](https://github.com/docker/notary) to ensure targets have not been tampered
with.  There are two components of this package, a packager which packages groups
of files and posts them to cloud storage as part of a build process, and an updater
that checks for updated packages, downloads them from storage, validates them, and
if valid, installs the updates.

### Updater

The updater is intended to be included in an application that wants to receive automated
updates.
When the updater is invoked it performs actions as dictated in section 5.1 of the
[TUF Specification](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt).
When a package is initially installed it includes a copy of role files from Notary.  These
files are known as the local repository and are used to store the state of the local package.
When updates are performed, changes are recorded in the local repository. More details are
outlined in the TUF spec. 

### Packager

The packager is intended to be triggered when a successful build occurs.
The packager gathers build artifacts into a release package along with a manifest file,
posts them to cloud storage, and then updates Notary with the new build information.
The packager performs the following actions when
a tagged build happens:

1. It builds an install structure based on the instructions in the manifest file.  This
would potentially include file permissions, directory structures, symlinks, and
additional instructions such as whether or not to overwrite certain files,
or to run migrations. The packager will build an installer using go-bindata to pack
up all the distributable files, and embed it in a generated go program that does the
install.

2. It copies the installer package to the appropriate location in cloud storage. This location
will use the following format.
```
<top level bucket>/<globally unique name>
```  
The top level bucket would refer to staging or production areas. The globally
unique name is the same as the GUN used in Notary to identify this group of targets.

3. The package is registered with Notary where it is hashed and signed.

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
