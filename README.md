# iRODS FUSE
FUSE implementation of iRODS Client written in Golang

## What is it?
Users are able to `mount` an `iRODS Collection` (multiple `Collections` or `DataObjects` are also available) on the directory hierarchy. Doing so, data stored on `iRODS` can be accessed via the directory hierarchy as if they are in local disks.

## Download pre-built binaries
Pre-built binaries can be found in `Release` in the repository. Checkout tarballs attached as assets in a release.

iRODS FUSE only works on Linux systems. MacOS (osx) is not supported as FUSE library is not open-source anymore. The binaries run on any Linux distros (e.g., Ubuntu 18.x, Ubuntu 20.x, CentOS 7, or CentOS 8) without requiring any dependencies. Use correct release binaries for your OS and architecture.

Links for iRODS FUSE: [https://github.com/cyverse/irodsfs/releases](https://github.com/cyverse/irodsfs/releases)

## Build from source

### Prerequisite - libFUSE
iRODS FUSE requires `libFUSE` library to provide file system mount in linux. `libFUSE` can be installed using linux package managers, such as `yum` or `apt`.

In Ubuntu,
```shell script
sudo apt-get install -y fuse
```

In CentOS,
```shell script
sudo yum install -y fuse
```

### Prerequisite - privileged access in Docker
**This only applies to users who run iRODS FUSE inside docker containers**

To use `libFUSE` in Docker containers, users should launch the docker container in privileged mode using `--privileged` option.
```shell script
docker run -ti --privileged <docker_image_name> /bin/bash
```  

### Prerequisite - Go
iRODS FUSE is written in `Go`. So `Go` is required to build iRODS FUSE. Note that once iRODS FUSE is built, it does not require `Go` for running.
To install `Go`, please refer [official installation guide](https://golang.org/doc/install).

### Prerequisite - Build essentials
To build, some common build essentials, such as `Make`, are required.

In Ubuntu,
```shell script
sudo apt-get install -y make
```

In CentOS,
```shell script
sudo yum install -y make
```

### Build
Clone the source repository using `git` or download the `zip` file of the source.

Clone the source repository using `git` and build.
```shell script
git clone https://github.com/cyverse/irodsfs
cd irodsfs
make build
```

Download the `zip` file of the source and build.
```shell script
curl -L -o irodsfs.zip https://github.com/cyverse/irodsfs/archive/refs/heads/main.zip
unzip irodsfs.zip
cd irodsfs-main
make build
```

After successful build, you will be able to find the binary in bin directory.

## Command-line Options

```
Usage:
  irodsfs [flags] [mount_point]

Flags:
  -c, --config string          Config file or directory (default: ~/.irods)
  -u, --username string        iRODS username
      --client_username string iRODS client username (for proxy auth)
  -p, --password string        iRODS password
      --url string             iRODS URL (e.g., irods://user:pass@host:port/zone/path)
  -f, --foreground             Run in foreground (default: run as daemon)
  -d, --debug                  Enable debug mode
      --readonly               Mount read-only
      --uid int                UID of file/directory owner (default: current user)
      --gid int                GID of file/directory owner (default: current group)
      --sys_user string        System user of file/directory owner
      --read_ahead_max int     Read-ahead buffer size in bytes
      --read_write_max int     Max read/write size in bytes
      --no_transaction         Disable iRODS transaction (may improve performance)
  -o, --fuse_option strings    Additional FUSE mount options
      --pool_endpoint string   iRODS FUSE Pool Service endpoint
      --data_root string       Data root directory path
      --log_path string        Log file path
      --instance_id string     Instance ID
  -v, --version                Print version
  -h, --help                   Print help
```

## How to use?
### Mount an iRODS Collection using URL
An iRODS user `iychoi` mounts a collection `/iplant/home/iychoi` in iRODS Server `data.cyverse.org` on a local directory `/mount/irods`.

- iRODS User: `iychoi`
- iRODS Password: `my_password`
- iRODS Host: `data.cyverse.org`
- iRODS Port: `1247`
- iRODS Zone: `iplant`
- iRODS Collection to mount: `/iplant/home/iychoi`
- Local directory to mount: `/mount/irods`

Run `irodsfs`.
```shell script
./bin/irodsfs --url irods://iychoi:my_password@data.cyverse.org:1247/iplant/home/iychoi /mount/irods
```

After mounting, `irodsfs` will be executed in the background. Use `-f` to run in foreground instead.

Test access the mount.
```shell script
ls /mount/irods
```

### Mount an iRODS Collection using a config YAML file

An iRODS user `iychoi` mounts a collection `/iplant/home/iychoi` in iRODS Server `data.cyverse.org` on a local directory `/mount/irods`.

- iRODS User: `iychoi`
- iRODS Password: `my_password`
- iRODS Host: `data.cyverse.org`
- iRODS Port: `1247`
- iRODS Zone: `iplant`
- iRODS Collection to mount: `/iplant/home/iychoi`
- Local directory to mount: `/mount/irods`

Create a `config.yaml` file.
```yaml
irods_host: data.cyverse.org
irods_port: 1247
irods_user_name: iychoi
irods_zone_name: iplant
irods_user_password: my_password

path_mappings:
  - irods_path: /iplant/home/iychoi
    mapping_path: /
    resource_type: dir
```

Then run `irodsfs` with `--config` or `-c` option.
```shell script
./bin/irodsfs -c config.yaml /mount/irods
```

After mounting, `irodsfs` will be executed in the background.

Test access the mount.
```shell script
ls /mount/irods
```

### Mount an iRODS Collection with PAM Authentication and SSL
An iRODS user `iychoi` mounts a collection `/iplant/home/iychoi` in iRODS Server `data.cyverse.org` on a local directory `/mount/irods` with PAM Authentication (with SSL).

- iRODS User: `iychoi`
- iRODS Password: `my_password`
- iRODS Host: `data.cyverse.org`
- iRODS Port: `1247`
- iRODS Zone: `iplant`
- iRODS Collection to mount: `/iplant/home/iychoi`
- Local directory to mount: `/mount/irods`
- Authentication Scheme: `pam_password`
- CA Cert File: `/home/iychoi/.irods/ca_cert.pem`
- Encryption Key Size: `32`
- Encryption Algorithm: `AES-256-CBC`
- Encryption Salt Size: `8`
- Hash Rounds: `16`

Create a `config.yaml` file.
```yaml
irods_host: data.cyverse.org
irods_port: 1247
irods_user_name: iychoi
irods_zone_name: iplant
irods_user_password: my_password

irods_authentication_scheme: "pam_password"
irods_ssl_ca_certificate_file: "/home/iychoi/.irods/ca_cert.pem"
irods_encryption_key_size: 32
irods_encryption_algorithm: "AES-256-CBC"
irods_encryption_salt_size: 8
irods_encryption_num_hash_rounds: 16

path_mappings:
  - irods_path: /iplant/home/iychoi
    mapping_path: /
    resource_type: dir
```

Then run `irodsfs` with `--config` or `-c` option.
```shell script
./bin/irodsfs -c config.yaml /mount/irods
```

After mounting, `irodsfs` will be executed in the background.

Test access the mount.
```shell script
ls /mount/irods
```

## Mount multiple iRODS Collections or Data Objects
An iRODS user `iychoi` mounts a collection `/iplant/home/iychoi/mount1` and `/iplant/home/iychoi/mount2` in iRODS Server `data.cyverse.org` under a local directory `/mount/irods`.

- iRODS User: `iychoi`
- iRODS Host: `data.cyverse.org`
- iRODS Port: `1247`
- iRODS Zone: `iplant`
- iRODS Collections to mount: `/iplant/home/iychoi/mount1` and `/iplant/home/iychoi/mount2`
- Local directory to mount: `/mount/irods`

Create a `config.yaml` file.
```yaml
irods_host: data.cyverse.org
irods_port: 1247
irods_user_name: iychoi
irods_zone_name: iplant
irods_user_password: my_password

path_mappings:
  - irods_path: /iplant/home/iychoi/mount1
    mapping_path: /mount1
    resource_type: dir
  - irods_path: /iplant/home/iychoi/mount2
    mapping_path: /mount2
    resource_type: dir
```

Then run `irodsfs` with `--config` or `-c` option.
```shell script
./bin/irodsfs -c config.yaml /mount/irods
```

After mounting, `irodsfs` will be executed in the background.

Test access the mount.
```shell script
ls /mount/irods
```

### Mount User's iRODS Home Collection using iCommands config (~/.irods)

An iRODS user `iychoi` has iCommands config in `~/.irods`.

Run `irodsfs` without any `--config` or `-c` option.
```shell script
./bin/irodsfs /mount/irods
```

After mounting, `irodsfs` will be executed in the background.

Test access the mount.
```shell script
ls /mount/irods
```

### Using iRODS FUSE Pool Service

iRODS FUSE can connect to an `irodsfs-pool` service to share iRODS connections across multiple mount instances, reducing the number of connections to the iRODS server.

```shell script
./bin/irodsfs -c config.yaml --pool_endpoint localhost:8021 /mount/irods
```

Or set it in the config file:
```yaml
pool_endpoint: "localhost:8021"
```

### Change Log Level

The log level can be set using `log_level` in the configuration file.

There are 6 log levels configurable (case-insensitive):
- "PANIC"
- "FATAL"
- "WARN"
- "INFO"
- "DEBUG"
- "TRACE"

To set the log level, add a `log_level` field to the config file.

```yaml
irods_host: data.cyverse.org
irods_port: 1247
irods_user_name: iychoi
irods_zone_name: iplant
irods_user_password: my_password
log_level: FATAL

path_mappings:
  - irods_path: /iplant/home/iychoi
    mapping_path: /
    resource_type: dir
```

### Read-only Mount

To mount a collection as read-only, use the `--readonly` flag or set `readonly: true` in the config file.

```shell script
./bin/irodsfs -c config.yaml --readonly /mount/irods
```

### Unmount

It is recommended to use `fusermount` command to unmount iRODS FUSE as it does not require admin permission.

```shell script
fusermount -u /mount/irods
```

It may fail unmounting with `device is busy` error if you have processes accessing the mount (e.g., shell). In the case, close the processes first and retry unmounting.
Otherwise, you can also try `lazy-unmount`, which will mark to unmount after the processes using the mount are closed.

```shell script
fusermount -u -z /mount/irods
```

It is also possible to use `umount` command to unmount iRODS FUSE. But in this case, you will need admin permission (or `sudo`).

```shell script
sudo umount /mount/irods
```

## License

Copyright (c) 2010-2021, The Arizona Board of Regents on behalf of The University of Arizona

All rights reserved.

Developed by: CyVerse as a collaboration between participants at BIO5 at The University of Arizona (the primary hosting institution), Cold Spring Harbor Laboratory, The University of Texas at Austin, and individual contributors. Find out more at http://www.cyverse.org/.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of CyVerse, BIO5, The University of Arizona, Cold Spring Harbor Laboratory, The University of Texas at Austin, nor the names of other contributors may be used to endorse or promote products derived from this software without specific prior written permission.


Please check [LICENSE](https://github.com/cyverse/irodsfs/tree/master/LICENSE) file.
