# Updater Example Application

This example demonstrates a simple application that uses Updater.

### Set Up

1. Create a directory to hold the local TUF role files. For example in `example/cmd`
type `mkdir repo`.
2. Create a staging directory where the Updater will place the validated files
that it downloads and validates. `mkdir staging `.
3. Set up Notary
  - Clone a local copy of Notary ` git clone ssh://git@github.com/docker/notary `
  - cd to the Notary project root.
  - Start up a local Notary server and copy the config file and testing
  certificates to your local Notary directory.
  ```
  $ docker-compose build
  $ docker-compose up -d
  $ mkdir -p ~/.notary && cp cmd/notary/config.json cmd/notary/root-ca.crt ~/.notary
  ```
  - Add `127.0.0.1  notary-server` to your `/etc/hosts` file.

4. Create a Notary repository, using a descriptive GUN (Globally Unique Identifier)
```
$ notary init kolide/greeter/darwin
```
Notary will prompt you to create several passwords for the keys it produces. By convention the target name is of the form <version>/<file>  

5. Add a target to your new repository. The `-p` flag will cause the added
target to be published immediately.
```
$ notary add kolide/greeter/darwin latest/target myfile.tgz -p
```

6. Upload the files you added to notary to the mirror. In a production environment this would be something like a public s3 bucket or static file server. 
In this example, you just have to add it to the `filerepo/$GUN` folder. The example will server the path on port 8888.
```
├── README.md
├── filerepo
│   └── kolide
│       └── greeter
│           └── darwin
│               └── latest
│                   └── target
```

*Important! Do not modify the target file in any way before uploading it to the mirror.*  
Updater expects to find targets hosted on the mirror at a URL of the form

7. Create your local repository.  cd to the `repo` directory you defined in
step 1 and run the following curl commands to get the necessary files from Notary.  

Using the provided script:

  ```Go
  go run main.go -bootstrap
  ```

or manually with curl:

  ``` bash
  $ curl -k https://notary-server:4443/v2/kolide/greeter/darwin/_trust/tuf/root.json > root.json
  $ curl -k https://notary-server:4443/v2/kolide/greeter/darwin/_trust/tuf/snapshot.json > snapshot.json
  $ curl -k https://notary-server:4443/v2/kolide/greeter/darwin/_trust/tuf/timestamp.json > timestamp.json
  $ curl -k https://notary-server:4443/v2/kolide/greeter/darwin/_trust/tuf/targets.json > targets.json
  ```
8. Define your settings in the example program.

  ``` go
  settings := updater.Settings{
    LocalRepoPath:      path.Join(baseDir, "repo"),
    NotaryURL:          "https://notary-server:4443",
    StagingPath:        path.Join(baseDir, "staging"),
    GUN:                "kolide/greeter/darwin",
    TargetName:         "latest/target",
    InsecureSkipVerify: true,
    MirrorURL:          "https://storage.googleapis.com/kolide_test_mirror",
  }
  ```
9. Run it! Note in this example the repo and staging directory are located relative
to the current working directory.
  ```
  $ go run main.go
  ```
10. If you want to see the example program handle an update add another target.  The easy
way to do this is just re-add the file in Step 5. Even though you are adding the same
file, Notary will detect the the timestamp has changed and trigger and update.  


### Full usage

```
Usage of ./example:
  -base-directory string
    	the directory where all the things are (default "./")
  -bootstrap
    	set up local repository for the GUN from the local notary-server
  -filerepo string
    	path to file repo which will serve static assets (default "filerepo")
  -gun string
    	the globally unique identifier (default "kolide/greeter/darwin")
  -server-certificates string
    	path to folder with server certs. must be named cert.pem and key.pem respectively (default "../../test/server")
```
