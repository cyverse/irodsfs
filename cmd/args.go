package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cyverse/go-irodsclient/client"
	"github.com/cyverse/irodsfs/pkg/irodsfs"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

const (
	ChildProcessArgument = "child_process"
	iRODSProtocol        = "irods://"
)

type FuseOptions []string

func (f *FuseOptions) String() string {
	return strings.Join(*f, " ")
}

func (f *FuseOptions) Set(val string) error {
	*f = append(*f, val)
	return nil
}

// IRODSAccessURL ...
type IRODSAccessURL struct {
	User     string
	Password string
	Host     string
	Port     int
	Zone     string
	Path     string
}

func parseIRODSURL(inputURL string) (*IRODSAccessURL, error) {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "parseIRODSURL",
	})

	u, err := url.Parse(inputURL)
	if err != nil {
		logger.WithError(err).Error("Error occurred while parsing source URL")
		return nil, err
	}

	user := ""
	password := ""

	if u.User != nil {
		uname := u.User.Username()
		if len(uname) > 0 {
			user = uname
		}

		if pwd, ok := u.User.Password(); ok {
			password = pwd
		}
	}

	host := ""
	host = u.Hostname()

	port := 1247
	if len(u.Port()) > 0 {
		port64, err := strconv.ParseInt(u.Port(), 10, 32)
		if err != nil {
			logger.WithError(err).Error("Error occurred while parsing source URL's port number")
			return nil, err
		}
		port = int(port64)
	}

	fullpath := path.Clean(u.Path)
	zone := ""
	irodsPath := "/"
	if len(fullpath) == 0 || fullpath[0] != '/' {
		err = fmt.Errorf("path (%s) must contain an absolute path", u.Path)
		logger.Error(err)
		return nil, err
	}

	pos := strings.Index(fullpath[1:], "/")
	if pos > 0 {
		zone = strings.Trim(fullpath[1:pos+1], "/")
		irodsPath = fullpath // starts with zone
	} else if pos == -1 {
		// no path
		zone = strings.Trim(fullpath[1:], "/")
		irodsPath = fullpath
	}

	if len(zone) == 0 || len(irodsPath) == 0 {
		err = fmt.Errorf("path (%s) must contain an absolute path", inputURL)
		logger.Error(err)
		return nil, err
	}

	return &IRODSAccessURL{
		User:     user,
		Password: password,
		Host:     host,
		Port:     port,
		Zone:     zone,
		Path:     irodsPath,
	}, nil
}

func inputMissingParams(config *irodsfs.Config, stdinClosed bool) error {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "inputMissingParams",
	})

	if len(config.ProxyUser) == 0 {
		if stdinClosed {
			err := fmt.Errorf("ProxyUser is not set")
			logger.Error(err)
			return err
		}

		fmt.Print("Username: ")
		fmt.Scanln(&config.ProxyUser)
	}

	if len(config.ClientUser) == 0 {
		if stdinClosed {
			err := fmt.Errorf("ClientUser is not set")
			logger.Error(err)
			return err
		}

		config.ClientUser = config.ProxyUser
	}

	if len(config.Password) == 0 {
		if stdinClosed {
			err := fmt.Errorf("Password is not set")
			logger.Error(err)
			return err
		}

		fmt.Print("Password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Print("\n")
		if err != nil {
			logger.WithError(err).Error("Error occurred while reading password")
			return err
		}

		config.Password = string(bytePassword)
	}

	return nil
}

func processArguments() (*irodsfs.Config, error, bool) {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "processArguments",
	})

	var version bool
	var help bool
	var fuseOptions FuseOptions
	var mappingFilePath string
	var configFilePath string
	var operationTimeout string
	var connectionIdleTimeout string
	var metadataCacheTimeout string
	var metadataCacheCleanupTime string

	config := irodsfs.NewDefaultConfig()

	// Parse parameters
	flag.BoolVar(&version, "version", false, "Print client version information")
	flag.BoolVar(&version, "v", false, "Print client version information (shorthand form)")
	flag.BoolVar(&help, "h", false, "Print help")
	flag.StringVar(&mappingFilePath, "mapping", "", "Set Path Mapping YAML File")
	flag.StringVar(&configFilePath, "config", "", "Set Config YAML File")
	flag.BoolVar(&config.Foreground, "f", false, "Run in foreground")
	flag.BoolVar(&config.AllowOther, "allow_other", false, "Allow access from other users")
	flag.BoolVar(&config.ChildProcess, ChildProcessArgument, false, "")
	flag.StringVar(&config.Host, "host", "", "Set iRODS host")
	flag.IntVar(&config.Port, "port", 1247, "Set iRODS port")
	flag.StringVar(&config.Zone, "zone", "", "Set iRODS zone")
	flag.StringVar(&config.ProxyUser, "proxyuser", "", "Set iRODS proxy user")
	flag.StringVar(&config.ClientUser, "clientuser", "", "Set iRODS client user")
	flag.StringVar(&config.ProxyUser, "user", "", "Set iRODS user")
	flag.StringVar(&config.ProxyUser, "u", "", "Set iRODS user (shorthand form)")
	flag.StringVar(&config.Password, "password", "", "Set iRODS client password")
	flag.StringVar(&config.Password, "p", "", "Set iRODS client password (shorthand form)")
	flag.IntVar(&config.ReadAheadMax, "readahead", irodsfs.ReadAheadMaxDefault, "Set read-ahead size")
	flag.IntVar(&config.ConnectionMax, "connectionmax", irodsfs.ConnectionMaxDefault, "Set max data transfer connections")
	flag.StringVar(&operationTimeout, "operationtimeout", "", "Set filesystem operation timeout")
	flag.StringVar(&connectionIdleTimeout, "connectionidletimeout", "", "Set idle data transfer timeout")
	flag.StringVar(&metadataCacheTimeout, "metadatacachetimeout", "", "Set filesystem metadata cache timeout")
	flag.StringVar(&metadataCacheCleanupTime, "metadatacachecleanuptime", "", "Set filesystem metadata cache cleanup time")
	flag.StringVar(&config.FileBufferStoragePath, "filecachestoragepath", irodsfs.FileBufferStoragePathDefault, "Set file cache storage path")
	flag.Int64Var(&config.FileBufferSizeMax, "filecachesizemax", irodsfs.FileBufferSizeMaxDefault, "Set file cache max size")
	flag.Var(&fuseOptions, "o", "Other fuse options")
	flag.StringVar(&config.LogPath, "log", "", "Set log file path")

	flag.Parse()

	if version {
		info, err := client.GetVersionJSON()
		if err != nil {
			logger.WithError(err).Error("Could not get client version info")
			return nil, err, true
		}

		fmt.Println(info)
		return nil, nil, true
	}

	if help {
		flag.Usage()
		return nil, nil, true
	}

	if len(config.LogPath) > 0 {
		logFile, err := os.OpenFile(config.LogPath, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			logger.WithError(err).Error("Could not create log file - %s", config.LogPath)
		} else {
			log.SetOutput(logFile)
		}
	}

	stdinClosed := false
	if len(configFilePath) > 0 {
		if configFilePath == "-" {
			// read from stdin
			stdinReader := bufio.NewReader(os.Stdin)
			yamlBytes, err := ioutil.ReadAll(stdinReader)
			if err != nil {
				logger.WithError(err).Error("Could not read STDIN")
				return nil, err, true
			}

			err = yaml.Unmarshal(yamlBytes, &config)
			if err != nil {
				return nil, fmt.Errorf("YAML Unmarshal Error - %v", err), true
			}

			stdinClosed = true
		} else {
			// read config
			configFileAbsPath, err := filepath.Abs(configFilePath)
			if err != nil {
				logger.WithError(err).Errorf("Could not access the local yaml file %s", configFilePath)
				return nil, err, true
			}

			fileinfo, err := os.Stat(configFileAbsPath)
			if err != nil {
				logger.WithError(err).Errorf("local yaml file (%s) error", configFileAbsPath)
				return nil, err, true
			}

			if fileinfo.IsDir() {
				logger.WithError(err).Errorf("local yaml file (%s) is not a file", configFileAbsPath)
				return nil, fmt.Errorf("local yaml file (%s) is not a file", configFileAbsPath), true
			}

			yamlBytes, err := ioutil.ReadFile(configFileAbsPath)
			if err != nil {
				logger.WithError(err).Errorf("Could not read the local yaml file %s", configFileAbsPath)
				return nil, err, true
			}

			err = yaml.Unmarshal(yamlBytes, &config)
			if err != nil {
				return nil, fmt.Errorf("YAML Unmarshal Error - %v", err), true
			}
		}
	}

	if len(mappingFilePath) > 0 {
		// inputPath can be a local file
		mappingFileAbsPath, err := filepath.Abs(mappingFilePath)
		if err != nil {
			logger.WithError(err).Errorf("Could not access the local yaml file %s", mappingFilePath)
			return nil, err, true
		}

		fileinfo, err := os.Stat(mappingFileAbsPath)
		if err != nil {
			logger.WithError(err).Errorf("local yaml file (%s) error", mappingFileAbsPath)
			return nil, err, true
		}

		if fileinfo.IsDir() {
			logger.WithError(err).Errorf("local yaml file (%s) is not a file", mappingFileAbsPath)
			return nil, fmt.Errorf("local yaml file (%s) is not a file", mappingFileAbsPath), true
		}

		yamlBytes, err := ioutil.ReadFile(mappingFileAbsPath)
		if err != nil {
			logger.WithError(err).Errorf("Could not read the local yaml file %s", mappingFileAbsPath)
			return nil, err, true
		}

		pathMappings := []irodsfs.PathMapping{}
		err = yaml.Unmarshal(yamlBytes, &pathMappings)
		if err != nil {
			return nil, fmt.Errorf("YAML Unmarshal Error - %v", err), true
		}

		config.PathMappings = pathMappings
	}

	// time
	if len(operationTimeout) > 0 {
		timeout, err := time.ParseDuration(operationTimeout)
		if err != nil {
			logger.WithError(err).Error("Could not parse Operation Timeout parameter into time.duration")
			return nil, err, true
		}

		config.OperationTimeout = timeout
	}

	if len(connectionIdleTimeout) > 0 {
		timeout, err := time.ParseDuration(connectionIdleTimeout)
		if err != nil {
			logger.WithError(err).Error("Could not parse Connection Idle Timeout parameter into time.duration")
			return nil, err, true
		}

		config.ConnectionIdleTimeout = timeout
	}

	if len(metadataCacheTimeout) > 0 {
		timeout, err := time.ParseDuration(metadataCacheTimeout)
		if err != nil {
			logger.WithError(err).Error("Could not parse Metadata Cache Timeout parameter into time.duration")
			return nil, err, true
		}

		config.MetadataCacheTimeout = timeout
	}

	if len(metadataCacheCleanupTime) > 0 {
		timeout, err := time.ParseDuration(metadataCacheCleanupTime)
		if err != nil {
			logger.WithError(err).Error("Could not parse Metadata Cache Cleanup Time parameter into time.duration")
			return nil, err, true
		}

		config.MetadataCacheCleanupTime = timeout
	}

	// positional arguments
	mountPath := ""
	if len(config.PathMappings) > 0 {
		if flag.NArg() != 1 {
			flag.Usage()
			err := fmt.Errorf("Illegal arguments given, required mount target, but received %d", flag.NArg())
			logger.Error(err)
			return nil, err, true
		}

		mountPath = flag.Arg(0)
	} else {
		if flag.NArg() == 0 {
			flag.Usage()
			return nil, nil, true
		}

		if flag.NArg() != 2 {
			flag.Usage()
			err := fmt.Errorf("Illegal arguments given, required 2, but received %d (%s)", flag.NArg(), strings.Join(flag.Args(), " "))
			logger.Error(err)
			return nil, err, true
		}

		// first arg is shorthand form of config
		// the first argument contains irods://HOST:PORT/ZONE/inputPath...
		inputPath := flag.Arg(0)
		if strings.HasPrefix(inputPath, iRODSProtocol) {
			// inputPath can be a single iRODS collection stating with irods://,
			access, err := parseIRODSURL(inputPath)
			if err != nil {
				logger.WithError(err).Error("Could not parse iRODS source path")
				return nil, err, true
			}

			if len(access.Host) > 0 {
				config.Host = access.Host
			}

			if access.Port > 0 {
				config.Port = access.Port
			}

			if len(access.User) > 0 {
				config.ProxyUser = access.User
			}

			if len(access.Password) > 0 {
				config.Password = access.Password
			}

			if len(access.Zone) > 0 {
				config.Zone = access.Zone
			}

			if len(access.Path) > 0 {
				config.PathMappings = []irodsfs.PathMapping{
					irodsfs.NewPathMappingForDir(access.Path, "/", false),
				}
			}

			if len(config.ClientUser) == 0 {
				config.ClientUser = config.ProxyUser
			}
		}

		mountPath = flag.Arg(1)
	}

	err := inputMissingParams(config, stdinClosed)
	if err != nil {
		logger.WithError(err).Error("Could not input missing parameters")
		return nil, err, true
	}

	// the second argument is local directory that irodsfs will be mounted
	mountpoint, err := filepath.Abs(mountPath)
	if err != nil {
		logger.WithError(err).Errorf("Could not access the mount point %s", mountPath)
		return nil, err, true
	}

	config.MountPath = mountpoint

	return config, nil, false
}
