package commons

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/cyverse/irodsfs/commons"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func SetCommonFlags(command *cobra.Command) {
	command.Flags().BoolP("version", "v", false, "Print version")
	command.Flags().BoolP("help", "h", false, "Print help")
	command.Flags().BoolP("debug", "d", false, "Enable debug mode")
	command.Flags().BoolP("foreground", "f", false, "Run in foreground")

	command.Flags().Bool("readonly", false, "Set read-only")

	command.Flags().StringP("config", "c", commons.GetDefaultIRODSConfigPath(), "Set config file or directory")
	command.Flags().String("instance_id", "", "Set instance ID")
	command.Flags().String("log_path", "", "Set log file path")

	command.Flags().StringP("username", "u", "", "Set iRODS username")
	command.Flags().String("client_username", "", "Set iRODS client username")
	command.Flags().StringP("password", "p", "", "Set iRODS password")

	command.Flags().Int("read_ahead_max", 0, "Set read-ahead size")
	command.Flags().Int("read_write_max", 0, "Set read-write size")
	command.Flags().Bool("no_transaction", false, "Disable transaction for performance")

	command.Flags().Int("uid", os.Geteuid(), "Set UID of file/directory owner")
	command.Flags().Int("gid", os.Getegid(), "Set GID of file/directory owner")
	command.Flags().String("sys_user", "", "Set System User of file/directory owner")

	command.Flags().StringArrayP("fuse_option", "o", []string{}, "Set FUSE options")

	command.Flags().String("data_root", "", "Set data root dir path")

	command.Flags().String("pool_endpoint", "", "Set iRODS FUSE Pool Service endpoint")
	command.Flags().String("url", "U", "Set iRODS URL (e.g., irods://host:port/zone/path/to/collection)")
}

func ProcessCommonFlags(command *cobra.Command, args []string) (*commons.Config, bool, error) {
	logger := log.WithFields(log.Fields{})

	debug := false
	debugFlag := command.Flags().Lookup("debug")
	if debugFlag != nil && debugFlag.Changed {
		debug, _ = strconv.ParseBool(debugFlag.Value.String())
	}

	foreground := false
	foregroundFlag := command.Flags().Lookup("foreground")
	if foregroundFlag != nil && foregroundFlag.Changed {
		foreground, _ = strconv.ParseBool(foregroundFlag.Value.String())
	}

	readOnly := false
	readOnlyFlag := command.Flags().Lookup("readonly")
	if readOnlyFlag != nil {
		readOnly, _ = strconv.ParseBool(readOnlyFlag.Value.String())
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	helpFlag := command.Flags().Lookup("help")
	if helpFlag != nil && helpFlag.Changed {
		help, _ := strconv.ParseBool(helpFlag.Value.String())
		if help {
			PrintHelp(command)
			return nil, false, nil // stop here
		}
	}

	versionFlag := command.Flags().Lookup("version")
	if versionFlag != nil && versionFlag.Changed {
		version, _ := strconv.ParseBool(versionFlag.Value.String())
		if version {
			PrintVersion(command)
			return nil, false, nil // stop here
		}
	}

	readConfig := false
	var config *commons.Config
	stdinClosed := false

	configFlag := command.Flags().Lookup("config")
	if configFlag != nil {
		configPath := configFlag.Value.String()
		if len(configPath) > 0 {
			// read from a file
			if configPath != "-" {
				clientConfig, err := commons.NewConfigFromFile(commons.NewDefaultConfig(), configPath)
				if err != nil {
					logger.Error(err)
					return nil, false, err // stop here
				}

				// overwrite config
				config = clientConfig
				readConfig = true
			} else {
				// read from stdin
				stdinReader := bufio.NewReader(os.Stdin)
				dataBytes, err := io.ReadAll(stdinReader)
				if err != nil {
					readErr := errors.Wrap(err, "failed to read config from stdin")
					logger.Error(readErr)
					return nil, false, readErr // stop here
				}

				clientConfig, err := commons.NewConfigFromStdin(config, dataBytes)
				if err != nil {
					logger.Error(err)
					return nil, false, err // stop here
				}

				// overwrite config
				config = clientConfig
				stdinClosed = true
				readConfig = true
			}
		}
	}

	// default config
	if !readConfig {
		config = commons.NewDefaultConfig()
	}

	// prioritize command-line flag over config files
	if debug {
		log.SetLevel(log.DebugLevel)
		config.Debug = true
	}

	if foreground {
		config.Foreground = true
	}

	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if readOnly {
		config.Readonly = true
	}

	instanceIdFlag := command.Flags().Lookup("instance_id")
	if instanceIdFlag != nil && instanceIdFlag.Changed {
		instanceId := instanceIdFlag.Value.String()
		if len(instanceId) > 0 {
			config.InstanceID = instanceId
		}
	}

	logPathFlag := command.Flags().Lookup("log_path")
	if logPathFlag != nil && logPathFlag.Changed {
		logPath := logPathFlag.Value.String()
		if len(logPath) > 0 {
			config.LogPath = logPath
		}
	}

	dataRootFlag := command.Flags().Lookup("data_root")
	if dataRootFlag != nil && dataRootFlag.Changed {
		dataRoot := dataRootFlag.Value.String()
		if len(dataRoot) > 0 {
			config.DataRootPath = dataRoot
		}

		if len(config.LogPath) == 0 {
			config.LogPath = config.GetLogFilePath()
		}
	}

	irodsUrlFlag := command.Flags().Lookup("url")
	if irodsUrlFlag != nil && irodsUrlFlag.Changed {
		irodsUrl := irodsUrlFlag.Value.String()
		if len(irodsUrl) > 0 {
			// irods://HOST:PORT/ZONE/inputPath...
			err := config.FromIRODSUrl(irodsUrl)
			if err != nil {
				logger.Error(err)
				return nil, false, err // stop here
			}
		}
	}

	usernameFlag := command.Flags().Lookup("username")
	if usernameFlag != nil && usernameFlag.Changed {
		username := usernameFlag.Value.String()
		if len(username) > 0 {
			config.Username = username
		}
	}

	clientUsernameFlag := command.Flags().Lookup("client_username")
	if clientUsernameFlag != nil && clientUsernameFlag.Changed {
		clientUsername := clientUsernameFlag.Value.String()
		if len(clientUsername) > 0 {
			config.ClientUsername = clientUsername
		}
	}

	passwordFlag := command.Flags().Lookup("password")
	if passwordFlag != nil && passwordFlag.Changed {
		password := passwordFlag.Value.String()
		if len(password) > 0 {
			config.Password = password
		}
	}

	readAheadMaxFlag := command.Flags().Lookup("read_ahead_max")
	if readAheadMaxFlag != nil && readAheadMaxFlag.Changed {
		readAheadMax, err := strconv.ParseInt(readAheadMaxFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := errors.Wrapf(err, "failed to convert input %q to int64", readAheadMaxFlag.Value.String())
			logger.Error(parseErr)
			return nil, false, parseErr // stop here
		}

		if readAheadMax > 0 {
			config.ReadAheadMax = int(readAheadMax)
		}
	}

	readWriteMaxFlag := command.Flags().Lookup("read_write_max")
	if readWriteMaxFlag != nil && readWriteMaxFlag.Changed {
		readWriteMax, err := strconv.ParseInt(readWriteMaxFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := errors.Wrapf(err, "failed to convert input %q to int64", readWriteMaxFlag.Value.String())
			logger.Error(parseErr)
			return nil, false, parseErr // stop here
		}

		if readWriteMax > 0 {
			config.ReadWriteMax = int(readWriteMax)
		}
	}

	noTransactionFlag := command.Flags().Lookup("no_transaction")
	if noTransactionFlag != nil && noTransactionFlag.Changed {
		noTransaction, _ := strconv.ParseBool(noTransactionFlag.Value.String())
		config.Cache.StartNewTransaction = !noTransaction
	}

	uidFlag := command.Flags().Lookup("uid")
	if uidFlag != nil && uidFlag.Changed {
		uid, err := strconv.ParseInt(uidFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := errors.Wrapf(err, "failed to convert input %q to int", uidFlag.Value.String())
			logger.Error(parseErr)
			return nil, false, parseErr // stop here
		}

		if uid > 0 {
			config.UID = int(uid)
		}
	}

	gidFlag := command.Flags().Lookup("gid")
	if gidFlag != nil && gidFlag.Changed {
		gid, err := strconv.ParseInt(gidFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := errors.Wrapf(err, "failed to convert input %q to int", gidFlag.Value.String())
			logger.Error(parseErr)
			return nil, false, parseErr // stop here
		}

		if gid > 0 {
			config.GID = int(gid)
		}
	}

	sysUserFlag := command.Flags().Lookup("sys_user")
	if sysUserFlag != nil && sysUserFlag.Changed {
		sysUser := sysUserFlag.Value.String()
		if len(sysUser) > 0 {
			config.SystemUser = sysUser
		}
	}

	fuseOptionsFlag := command.Flags().Lookup("fuse_option")
	if fuseOptionsFlag != nil && fuseOptionsFlag.Changed {
		fuseOptionsString := fuseOptionsFlag.Value.String()
		fuseOptionsString = strings.Trim(fuseOptionsString, "[]")
		if len(fuseOptionsString) > 0 {
			fuseOptionsStringArray := strings.Split(fuseOptionsString, ",")
			config.FuseOptions = fuseOptionsStringArray
		}
	}

	poolEndpointFlag := command.Flags().Lookup("pool_endpoint")
	if poolEndpointFlag != nil && poolEndpointFlag.Changed {
		poolEndpoint := poolEndpointFlag.Value.String()
		if len(poolEndpoint) > 0 {
			config.PoolEndpoint = poolEndpoint
		}
	}

	// positional arguments
	mountPath := ""
	if len(args) == 0 {
		PrintHelp(command)
		return nil, false, errors.New("mount point is not provided") // stop here
	}

	mountPath = args[0]

	config.FixAuthConfiguration()

	if !stdinClosed {
		err := inputMissingParams(config)
		if err != nil {
			logger.Error(err)
			return nil, false, err // stop here
		}
	}

	// the second argument is local directory that irodsfs will be mounted
	mountpoint, err := filepath.Abs(mountPath)
	if err != nil {
		absErr := errors.Wrapf(err, "failed to get abs path for %q", mountPath)
		return nil, false, absErr // stop here
	}

	config.MountPath = mountpoint

	err = config.FixSystemUserConfiguration()
	if err != nil {
		logger.Error(err)
		return nil, false, err // stop here
	}
	config.FixPathMappings()

	err = config.Validate()
	if err != nil {
		logger.Error(err)
		return nil, false, err // stop here
	}

	return config, true, nil // continue
}

func PrintVersion(command *cobra.Command) error {
	info, err := commons.GetVersionJSON()
	if err != nil {
		return err
	}

	fmt.Println(info)
	return nil
}

func PrintHelp(command *cobra.Command) error {
	return command.Usage()
}

// inputMissingParams gets user inputs for parameters missing, such as username and password
func inputMissingParams(config *commons.Config) error {
	if len(config.Username) == 0 {
		config.Username = commons.Input("Username: ")
	}

	if len(config.ClientUsername) == 0 {
		config.ClientUsername = config.Username
	}

	if config.Username != "anonymous" {
		if len(config.Password) == 0 {
			config.Password = commons.InputPassword("iRODS Password")
		}
	}

	config.FixAuthConfiguration()

	return nil
}
