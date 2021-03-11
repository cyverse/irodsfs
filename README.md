# irodsfs
FUSE implementation of iRODS Client written in Golang



## Build
Build an executable using `Makefile`. The executable will be created under `bin`.
```shell script
make build
```

## Mount an iRODS Collection
Run `irodsfs` to mount a collection with following information.

- User: `iychoi`
- iRODS Host: `data.cyverse.org`
- iRODS Port: `1247` (Default, omitted) 
- Zone: `iplant`
- Collection: `/home/iychoi`
- Mount Path: `/mount/irods`

```shell script
./bin/irodsfs irods://iychoi@data.cyverse.org/iplant/home/iychoi /mount/irods
```

After mounting, `irodsfs` will be executed in the background. To unmount, use `umount` command.

```shell script
sudo umount -f /mount/irods
```

## Mount multiple iRODS Collections or Data Objects
Run `irodsfs` to mount multiple collections and data objects with custom path mappings.
A path mapping file in YAML format must be provided as the first positional argument.

- User: `iychoi`
- iRODS Host: `data.cyverse.org`
- iRODS Port: `1247` (Default, omitted) 
- Zone: `iplant`
- Path Mapping YAML File: `./examples/multi_collection_mapping.yaml`
- Mount Path: `/mount/irods`

```shell script
./irodsfs -u iychoi -host data.cyverse.org -zone iplant -mapping ../examples/multi_collection_mapping.yaml /mount/irods
```

After mounting, `irodsfs` will be executed in the background. To unmount, use `umount` command.

```shell script
sudo umount -f /mount/irods
```


## License

Copyright (c) 2010-2021, The Arizona Board of Regents on behalf of The University of Arizona

All rights reserved.

Developed by: CyVerse as a collaboration between participants at BIO5 at The University of Arizona (the primary hosting institution), Cold Spring Harbor Laboratory, The University of Texas at Austin, and individual contributors. Find out more at http://www.cyverse.org/.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of CyVerse, BIO5, The University of Arizona, Cold Spring Harbor Laboratory, The University of Texas at Austin, nor the names of other contributors may be used to endorse or promote products derived from this software without specific prior written permission.


Please check [LICENSE](https://github.com/cyverse/go-irodsclient/tree/master/LICENSE) file.
