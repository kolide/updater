# updater
Securely handles automated software updates.


## How It Works

Updater uses Google Cloud Storage to store update targets, and
[Notary](https://github.com/docker/notary) to ensure targets have not been tampered
with.  There are two components of this package, a publisher which packages groups
of files and posts them to cloud storage as part of a build process, and an updater
that checks for updated packages, downloads them from storage, validates, and
installs the updates.

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
<top level bucket>/<globally unique name>/<platform>/<version>
```  
The top level bucket would refer to staging or production areas. The version is a monotonically  
increasing value.

3. The package is registered with Notary where it is hashed and signed.

### Updater

The updater is intended to be invoked periodically from a process on a host system.
Then the updater is invoked it performs the following actions:

1. It checks for new releases.  It will install all new releases in sequence. For
example, if the current release is `N` then `N + 1, N + 2 ...` will be installed
until there are no more releases.

2. The release package will be downloaded from cloud storage and validated using
Notary.  If the validation passes, Updater will invoke installer which will install
files, create directories etc and perform
whatever restarts are necessary to pick up the changes.
