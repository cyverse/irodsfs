package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cyverse/irodsfs/pkg/commons"
	"github.com/cyverse/irodsfs/pkg/vfs"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

const (
	// ChildProcessArgument is a command-line parameter used to make the process as a child
	// used internally
	ChildProcessArgument = "child_process"
	// iRODSProtocol is a scheme for iRODS Access URL
	iRODSProtocol = "irods://"
)

// FuseOptions holds options for FUSE
type FuseOptions []string

// String returns FUSE options as a string
func (f *FuseOptions) String() string {
	return strings.Join(*f, " ")
}

// Set adds a new FUSE option
func (f *FuseOptions) Set(val string) error {
	*f = append(*f, val)
	return nil
}

// IRODSAccessURL is used to extract iRODS access information from iRODS Access URL (irods://host:port/zone/path)
type IRODSAccessURL struct {
	User     string
	Password string
	Host     string
	Port     int
	Zone     string
	Path     string
}

// parseIRODSURL parses iRODS Access URL string and returns IRODSAccessURL struct
func parseIRODSURL(inputURL string) (*IRODSAccessURL, error) {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "parseIRODSURL",
	})

	u, err := url.Parse(inputURL)
	if err != nil {
		logger.WithError(err).Errorf("failed to parse source URL %s", inputURL)
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
			logger.WithError(err).Errorf("failed to parse source URL's port number %s", u.Port())
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

// inputMissingParams gets user inputs for parameters missing, such as username and password
func inputMissingParams(config *commons.Config, stdinClosed bool) error {
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
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Print("\n")
		if err != nil {
			logger.WithError(err).Error("failed to read password")
			return err
		}

		config.Password = string(bytePassword)
	}

	return nil
}

// processArguments processes command-line parameters
func processArguments() (*commons.Config, *os.File, error, bool) {
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

	config := commons.NewDefaultConfig()

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
	flag.StringVar(&config.ProxyUser, "proxy_user", "", "Set iRODS proxy user")
	flag.StringVar(&config.ClientUser, "client_user", "", "Set iRODS client user")
	flag.StringVar(&config.ProxyUser, "user", "", "Set iRODS user")
	flag.StringVar(&config.ProxyUser, "u", "", "Set iRODS user (shorthand form)")
	flag.StringVar(&config.Password, "password", "", "Set iRODS client password")
	flag.StringVar(&config.Password, "p", "", "Set iRODS client password (shorthand form)")
	flag.IntVar(&config.ReadAheadMax, "readahead", commons.ReadAheadMaxDefault, "Set read-ahead size")
	flag.IntVar(&config.ConnectionMax, "connection_max", commons.ConnectionMaxDefault, "Set max data transfer connections")
	flag.StringVar(&operationTimeout, "operation_timeout", "", "Set filesystem operation timeout")
	flag.StringVar(&connectionIdleTimeout, "connection_idle_timeout", "", "Set idle data transfer timeout")
	flag.StringVar(&metadataCacheTimeout, "metadata_cache_timeout", "", "Set filesystem metadata cache timeout")
	flag.StringVar(&metadataCacheCleanupTime, "metadata_cache_cleanup_time", "", "Set filesystem metadata cache cleanup time")
	flag.Int64Var(&config.BufferSizeMax, "buffer_size_max", commons.BufferSizeMaxDefault, "Set file buffer max size")
	flag.Var(&fuseOptions, "o", "Other fuse options")
	flag.StringVar(&config.LogPath, "log", commons.GetDefaultLogFilePath(), "Set log file path")
	flag.StringVar(&config.MonitorURL, "monitor", "", "Set monitoring service URL")
	flag.StringVar(&config.AuthScheme, "auth_scheme", commons.AuthSchemeDefault, "Set authentication scheme (eg. native or pam)")
	flag.StringVar(&config.CACertificateFile, "ssl_ca_cert", "", "Set SSL CA cert file when auth_scheme is pam")
	flag.IntVar(&config.EncryptionKeySize, "ssl_key_size", commons.EncryptionKeySizeDefault, "Set SSL encryption key size when auth_scheme is pam")
	flag.StringVar(&config.EncryptionAlgorithm, "ssl_algorithm", commons.EncryptionAlgorithmDefault, "Set SSL encryption algorithm when auth_scheme is pam")
	flag.IntVar(&config.SaltSize, "ssl_salt_size", commons.SaltSizeDefault, "Set SSL encryption salt size when auth_scheme is pam")
	flag.IntVar(&config.HashRounds, "ssl_hash_rounds", commons.HashRoundsDefault, "Set SSL hash rounds when auth_scheme is pam")
	flag.IntVar(&config.UID, "uid", -1, "Set UID of file/directory owner")
	flag.IntVar(&config.GID, "gid", -1, "Set GID of file/directory owner")
	flag.StringVar(&config.SystemUser, "sys_user", "", "Set System User of file/directory owner")
	flag.StringVar(&config.PoolHost, "pool_host", "", "Set iRODS FUSE Lite Pool host")
	flag.IntVar(&config.PoolPort, "pool_port", 12020, "Set iRODS FUSE Lite Pool port")

	flag.Parse()

	if version {
		info, err := commons.GetVersionJSON()
		if err != nil {
			logger.WithError(err).Error("failed to get client version info")
			return nil, nil, err, true
		}

		fmt.Println(info)
		return nil, nil, nil, true
	}

	if help {
		flag.Usage()
		return nil, nil, nil, true
	}

	var logFile *os.File
	logFile = nil
	if config.LogPath == "-" || len(config.LogPath) == 0 {
		log.SetOutput(os.Stderr)
	} else {
		logFileHandle, err := os.OpenFile(config.LogPath, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			logger.WithError(err).Errorf("failed to create log file - %s", config.LogPath)
		} else {
			// use multi output - to output to file and stdout
			mw := io.MultiWriter(os.Stderr, logFileHandle)
			log.SetOutput(mw)
			logFile = logFileHandle
		}
	}

	logger.Infof("Logging to %s", config.LogPath)

	stdinClosed := false
	if len(configFilePath) > 0 {
		if configFilePath == "-" {
			// read from stdin
			stdinReader := bufio.NewReader(os.Stdin)
			yamlBytes, err := ioutil.ReadAll(stdinReader)
			if err != nil {
				logger.WithError(err).Error("failed to read STDIN")
				return nil, logFile, err, true
			}

			err = yaml.Unmarshal(yamlBytes, &config)
			if err != nil {
				return nil, logFile, fmt.Errorf("failed to unmarshal YAML - %v", err), true
			}

			stdinClosed = true
		} else {
			// read config
			configFileAbsPath, err := filepath.Abs(configFilePath)
			if err != nil {
				logger.WithError(err).Errorf("failed to access the local yaml file %s", configFilePath)
				return nil, logFile, err, true
			}

			fileinfo, err := os.Stat(configFileAbsPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to access the local yaml file %s", configFileAbsPath)
				return nil, logFile, err, true
			}

			if fileinfo.IsDir() {
				logger.WithError(err).Errorf("local yaml file %s is not a file", configFileAbsPath)
				return nil, logFile, fmt.Errorf("local yaml file %s is not a file", configFileAbsPath), true
			}

			yamlBytes, err := ioutil.ReadFile(configFileAbsPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to read the local yaml file %s", configFileAbsPath)
				return nil, logFile, err, true
			}

			err = yaml.Unmarshal(yamlBytes, &config)
			if err != nil {
				return nil, logFile, fmt.Errorf("failed to unmarshal YAML - %v", err), true
			}
		}
	}

	if len(mappingFilePath) > 0 {
		// inputPath can be a local file
		mappingFileAbsPath, err := filepath.Abs(mappingFilePath)
		if err != nil {
			logger.WithError(err).Errorf("failed to access the local yaml file %s", mappingFilePath)
			return nil, logFile, err, true
		}

		fileinfo, err := os.Stat(mappingFileAbsPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to access the local yaml file %s", mappingFileAbsPath)
			return nil, logFile, err, true
		}

		if fileinfo.IsDir() {
			logger.WithError(err).Errorf("local yaml file %s is not a file", mappingFileAbsPath)
			return nil, logFile, fmt.Errorf("local yaml file %s is not a file", mappingFileAbsPath), true
		}

		yamlBytes, err := ioutil.ReadFile(mappingFileAbsPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to read the local yaml file %s", mappingFileAbsPath)
			return nil, logFile, err, true
		}

		pathMappings := []vfs.PathMapping{}
		err = yaml.Unmarshal(yamlBytes, &pathMappings)
		if err != nil {
			return nil, logFile, fmt.Errorf("failed to unmarshal YAML - %v", err), true
		}

		config.PathMappings = pathMappings
	}

	// time
	if len(operationTimeout) > 0 {
		timeout, err := time.ParseDuration(operationTimeout)
		if err != nil {
			logger.WithError(err).Error("failed to parse Operation Timeout parameter into time.duration")
			return nil, logFile, err, true
		}

		config.OperationTimeout = timeout
	}

	if len(connectionIdleTimeout) > 0 {
		timeout, err := time.ParseDuration(connectionIdleTimeout)
		if err != nil {
			logger.WithError(err).Error("failed to parse Connection Idle Timeout parameter into time.duration")
			return nil, logFile, err, true
		}

		config.ConnectionIdleTimeout = timeout
	}

	if len(metadataCacheTimeout) > 0 {
		timeout, err := time.ParseDuration(metadataCacheTimeout)
		if err != nil {
			logger.WithError(err).Error("failed to parse Metadata Cache Timeout parameter into time.duration")
			return nil, logFile, err, true
		}

		config.MetadataCacheTimeout = timeout
	}

	if len(metadataCacheCleanupTime) > 0 {
		timeout, err := time.ParseDuration(metadataCacheCleanupTime)
		if err != nil {
			logger.WithError(err).Error("failed to parse Metadata Cache Cleanup Time parameter into time.duration")
			return nil, logFile, err, true
		}

		config.MetadataCacheCleanupTime = timeout
	}

	err := config.CorrectSystemUser()
	if err != nil {
		logger.WithError(err).Error("failed to correct system user configuration")
		return nil, logFile, err, true
	}

	// positional arguments
	mountPath := ""
	if flag.NArg() == 0 {
		flag.Usage()
		return nil, logFile, nil, true
	}

	lastArgIdx := flag.NArg() - 1
	mountPath = flag.Arg(lastArgIdx)

	if flag.NArg() == 2 {
		// first arg may be shorthand form of config
		// the first argument contains irods://HOST:PORT/ZONE/inputPath...
		inputPath := flag.Arg(0)
		if strings.HasPrefix(inputPath, iRODSProtocol) {
			// inputPath can be a single iRODS collection stating with irods://,
			access, err := parseIRODSURL(inputPath)
			if err != nil {
				logger.WithError(err).Error("failed to parse iRODS source path")
				return nil, logFile, err, true
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
				config.PathMappings = []vfs.PathMapping{
					{
						IRODSPath:      access.Path,
						MappingPath:    "/",
						ResourceType:   vfs.PathMappingDirectory,
						ReadOnly:       false,
						CreateDir:      false,
						IgnoreNotExist: false,
					},
				}
			}

			if len(config.ClientUser) == 0 {
				config.ClientUser = config.ProxyUser
			}
		}
	}

	err = inputMissingParams(config, stdinClosed)
	if err != nil {
		logger.WithError(err).Error("failed to input missing parameters")
		return nil, logFile, err, true
	}

	// the second argument is local directory that irodsfs will be mounted
	mountpoint, err := filepath.Abs(mountPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to access the mount point %s", mountPath)
		return nil, logFile, err, true
	}

	config.MountPath = mountpoint

	return config, logFile, nil, false
}
