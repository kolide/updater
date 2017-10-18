# Updater

Securely handles automated software updates.

The Updater is designed to download and install software updates from a mirror. Updater ensures that downloaded files have not been altered or otherwise tampered with using [TUF](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt) and  [Notary](https://github.com/docker/notary).

## Example

If you'e interested in a self-contained example application which uses this library to update itself, check out the [included example](./example/cmd/README.md). If you're interested in seeing an application which uses this library for a production use-case, look no further than the [implementation of Kolide's osquery autoupdater](https://github.com/kolide/launcher/blob/master/autoupdate/autoupdate.go).

## How It Works

Updater uses a mirror such as Google Cloud Storage to store update targets, and uses [Notary](https://github.com/docker/notary) to ensure that targets have not been tampered with. Therefore Notary must be set up and configured in order to use Updater to keep things up to date.

When the Updater is invoked it performs actions as dictated in section 5.1 of the [TUF Specification](https://github.com/theupdateframework/tuf/blob/develop/docs/tuf-spec.txt). When an application that uses Updater is released, it must be distributed with a copy of the current TUF repo from the Notary server.  These files are known as the local repository and are used to store state information about the local application artifacts that are managed by Updater. After a successful update has occurred, the local TUF repository is synchronized with the remote repository. Updater will periodically compare it's local repository with the remote repository hosted by Notary.  When the Notary repository has changed an update is trigged by the Updater, these updates either take the form of crypto key rotation or local file updates. See the example application included with this package for specific details for setting up an application to use updater.

## Security

Kolide contracted NCC Group to perform a security assessment of this library for it's compliance to the TUF specification and for any additional potential vulnerabilities. Through a partnership with NCC Group, we have made the report available for public review: [https://dl.kolide.com/doc/ncc_updater_audit.pdf](https://dl.kolide.com/doc/ncc_updater_audit.pdf).

## Development

To setup a working local development environment, you must install the following minimum toolset:

* [Go](https://golang.org/dl/) (1.8 or greater)
* [GNU Make](https://www.gnu.org/software/make/)
* [Docker](https://www.docker.com/products/overview#/install_the_platform)


If you're using MacOS or Linux, Make should be installed by default. If you are using Windows, you will need to install it separately.

Once you have those minimum requirements, you will need to install the dependent libraries. To do this, run the following:

```
make deps
```

To execute all of the tests that CI will execute, run the following from the root of the repository:

```
make test
```

## Notary Setup

Notary is comprised of server and client binaries. Notary sources and full documentation are [here](https://github.com/docker/notary).  Updater will use a Notary repository to detect and validate software updates. The Notary binaries can be built using the following commands:

```
git clone ssh://git@github.com/docker/notary
cd notary
make binaries
```

### Notary Server

 Notary server consists of three components, the Notary Signer, Server and a database.  Instructions on configuring and running these components can be found [here](https://github.com/docker/notary/blob/master/docs/running_a_service.md).  Updater supports ECDSA to verify signatures.  This option must be defined as the value of `key_algorithm` in the [Notary Server configuration](https://github.com/docker/notary/blob/master/docs/reference/server-config.md).

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

 Notary Server components must be set up and running before using Notary Client to bootstrap the repository.

### Bootstrapping a TUF Repository

Updater requires a TUF repository to validate and detect software updates. Notary Client must be installed and be in your search path to create and manage the TUF repository. Prebuilt versions of Notary Client can be found [here](https://github.com/docker/notary/releases) or it can be built from source as previously described. Notary Client must be properly configured prior to use. [Here](https://github.com/docker/notary/blob/master/docs/reference/client-config.md) are instructions for configuring the Notary Client. For the remainder of this section we'll assume we're using Updater to manage updates to fictitious software called Wingnut.  We will need to create a TUF repository to manage updated versions of Wingnut that will be hosted on a mirror.  We've previously set up Notary Server and it is available on `https://notary.wingnut.com`, and we have Notary Client installed on our local system.  First, define environment variables with good pass phrases for each Notary role.

```
NOTARY_DELEGATION_PASSPHRASE=<secret>
NOTARY_ROOT_PASSPHRASE=<secret>
NOTARY_SNAPSHOT_PASSPHRASE=<secret>
NOTARY_TARGETS_PASSPHRASE=<secret>
```

Define a GUN (Globally Unique Identifier) for Wingnut.  This GUN can be anything as long as it uniquely identifies our repository.  The following command will create and publish a TUF repository identified by the GUN `acme.co/wingnut`.

```
notary init acme.co/wingnut -p
```

If this is the first repository that we have created for this Notary installation a root key will be generated. This root key must be carefully managed since the root key anchors trust for all the other keys in the TUF repository. It is important to export it, and remove it from the local machine if it is not needed. The root key and its associated pass phrase should be stored safely. There is no way to recover the root key or its pass phrase if either is lost.  The following illustrates how to export the root key. First find the ID of the root key.

```
notary key list

ROLE        GUN                KEY ID                                                              LOCATION
----        ---                ------                                                              --------
root                           b8dc5cded1a8522a563a58c3ac7ad2eba51d6945999aa5864678fb5064bb6f9e    /Users/jam/.notary/private
snapshot    acme.co/wingnut    5e1221edd379be729f12f3cb69786758ee23a71067b6e25c62d10ccfe0c82f31    /Users/jam/.notary/private
targets     acme.co/wingnut    69338c3d0b556af446bba3fb87ca61fcdbcb8ff327a648cd85f1832238438d5e    /Users/jam/.notary/private
```

Then export the root key, remove it and store it somewhere safe.

```
notary key export --key b8dc5cded1a8522a563a58c3ac7ad2eba51d6945999aa5864678fb5064bb6f9e -o notary-root.key
```

Next we will create a delegation role named `targets/releases`. Delegations roles must be prefixed by `targets` but subsequent elements can be anything you want, for example `targets/some/role` is valid, `super/delegate` is not. See [advanced usage](https://github.com/docker/notary/blob/master/docs/advanced_usage.md) for more details on creating delegation roles.  Before we do anything, rotate the snapshot key so it will be managed by the Notary Server.

```
notary key rotate acme.co/wingnut snapshot -r
```

Next, create an x509 cert and a signing key for the delegate role `targets/releases` that we are creating. The easiest way to do this is to use Notary to generate the key. The following will generate the certificate `delegate.pem` and the key `delegate-key.pem`.

```
notary key generate ecdsa --role targets/releases -o delegate
```

Create and publish the delegate role.

```
notary delegation add acme.co/wingnut targets/releases delegate.pem --all-paths -p
```

A Notary Client user must import the private key in order to publish updates for the delegation role. Find the ID of the x509 cert for the delegate and add a path header to the private key you created earlier.  The key ID can be obtained by listing the delegates for your repository.

```
notary delegation list acme.co/wingnut

ROLE                PATHS             KEY IDS                                                             THRESHOLD
----                -----             -------                                                             ---------
targets/releases    "" <all paths>    06061078b3fefc16d5170cdfc3af6e8881d2d4a283e7a7b894c89402e3a5057d    1
```

Open the private key you created `delegate-key.pem` in a text editor and add the Key ID to the path header of the key.

```
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,f6aa527f4df1bf0586e5c78a5cf391bc
role: targets/releases
path: 06061078b3fefc16d5170cdfc3af6e8881d2d4a283e7a7b894c89402e3a5057d

y7yWNcOBsMiY7owqkXVKEzmlIJ4czs2t+oB7MceX7WZrxI3O51Fr2YYX7Q5+jiZF
iI1fszTUNu8f07bY/u0c36K6LiTQOIxiT5N2YMD5+sb4XRE9KUpSSOEVEWlMGopw
Xm//qxWRIzC4C5Tc11liQ9gfz3PJ3TX2gOoQJMtfq6k=
-----END EC PRIVATE KEY-----
```

Export the target key.

```
notary key export --key  69338c3d0b556af446bba3fb87ca61fcdbcb8ff327a648cd85f1832238438d5e  -o targets.pem
```

#### Updating the TUF Repository

The Updater reads the TUF repository from the Notary server to detect and validate software updates.  After the updated file has been copied to a mirror, that file must be added to Notary.  Notary client will need to be installed on the system and an exact copy of the updated file must be available.  The target and delegate keys, and their respective passwords must also be available.  First define environment variables with the pass phrases for the targets and delegate roles.

```
NOTARY_DELEGATION_PASSPHRASE=<secret>
NOTARY_TARGETS_PASSPHRASE=<secret>
```

Also the target and delegate keys must be imported.

```
notary key import delegate-key.pem targets.pem
```

Once the keys are imported and the pass phrases are available you're ready to add the new or updated target to Notary. Lets say for example you have uploaded a new darwin build of Wingnut to your distribution mirror and you want to update the `darwin/wingnut-stable.tar.gz` target in the Notary repository. The following command would publish the target to the targets/releases delegate so that it would be picked up and installed by Updater. Assume the path to the build artifact is `build/wingnet.tar.gz`

```
notary add acme.co/wingnut darwin/wingnut-stable.tar.gz build/wingnut.tar.gz --roles targets/releases -p
```

Verify the target was added.

```
notary list acme.co/wingnut

NAME               DIGEST                                                              SIZE (BYTES)    ROLE
----               ------                                                              ------------    ----
acme.co/wingnut    3299c340c89c6602bdb6a80149554ab717db99bdcc7ae034bb69a95aeef68044    4357824         targets/releases
```
