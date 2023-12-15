package commons

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"

	"github.com/cyverse/irodsfs/commons"
	"golang.org/x/term"
	"golang.org/x/xerrors"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	ChildProcessArgument = "child_process"
)

func SetCommonFlags(command *cobra.Command) {
	command.Flags().BoolP("version", "v", false, "Print version")
	command.Flags().BoolP("help", "h", false, "Print help")
	command.Flags().BoolP("debug", "d", false, "Enable debug mode")
	command.Flags().String("log_level", "", "Set log level (default is INFO)")
	command.Flags().Bool("profile", false, "Enable profiling")
	command.Flags().BoolP("foreground", "f", false, "Run in foreground")
	command.Flags().Bool("allow_other", false, "Allow access from other users")

	command.Flags().StringP("config", "c", "", "Set config file (yaml)")
	command.Flags().String("instance_id", "", "Set instance ID")
	command.Flags().String("log_path", "", "Set log file path")

	command.Flags().String("host", "", "Set iRODS host")
	command.Flags().Int("port", 1247, "Set iRODS port")
	command.Flags().String("zone", "", "Set iRODS zone")
	command.Flags().String("proxy_user", "", "Set iRODS proxy user")
	command.Flags().String("client_user", "", "Set iRODS client user")
	command.Flags().StringP("user", "u", "", "Set iRODS user")
	command.Flags().StringP("password", "p", "", "Set iRODS password")
	command.Flags().String("resource", "", "Set iRODS resource")

	command.Flags().String("path_mapping_file", "", "Set path mapping file (yaml)")
	command.Flags().Int("readahead", commons.ReadAheadMaxDefault, "Set read-ahead size")
	command.Flags().Int("connection_max", commons.ConnectionMaxDefault, "Set max data transfer connections")
	command.Flags().Duration("operation_timeout", commons.OperationTimeoutDefault, "Set filesystem operation timeout")
	command.Flags().Duration("connection_idle_timeout", commons.ConnectionIdleTimeoutDefault, "Set idle connection timeout")
	command.Flags().Duration("metadata_cache_timeout", commons.MetadataCacheTimeoutDefault, "Set file system metadata cache timeout")
	command.Flags().Duration("metadata_cache_cleanup_time", commons.MetadataCacheCleanupTimeDefault, "Set file system metadata cache cleanup time")
	command.Flags().Bool("no_permission_check", false, "Disable permission check for performance")
	command.Flags().Bool("no_set_xattr", false, "Disable set xattr")
	command.Flags().Bool("no_transaction", false, "Disable transaction for performance")

	command.Flags().Int("uid", -1, "Set UID of file/directory owner")
	command.Flags().Int("gid", -1, "Set GID of file/directory owner")
	command.Flags().String("sys_user", "", "Set System User of file/directory owner")

	command.Flags().StringArrayP("fuse_option", "o", []string{}, "Set FUSE options")

	command.Flags().String("data_root", "", "Set data root dir path")

	command.Flags().Int("profile_port", -1, "Set profile service port")
	command.Flags().String("pool_endpoint", "", "Set iRODS FUSE Lite Pool Service endpoint")
	command.Flags().String("monitor_url", "", "Set monitoring service URL")

	command.Flags().Bool(ChildProcessArgument, false, "")
}

func ProcessCommonFlags(command *cobra.Command, args []string) (*commons.Config, io.WriteCloser, bool, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "ProcessCommonFlags",
	})

	logLevel := ""
	logLevelFlag := command.Flags().Lookup("log_level")
	if logLevelFlag != nil {
		logLevelStr := logLevelFlag.Value.String()
		logLevel = logLevelStr
	}

	debug := false
	debugFlag := command.Flags().Lookup("debug")
	if debugFlag != nil {
		debug, _ = strconv.ParseBool(debugFlag.Value.String())
	}

	foreground := false
	foregroundFlag := command.Flags().Lookup("foreground")
	if foregroundFlag != nil {
		foreground, _ = strconv.ParseBool(foregroundFlag.Value.String())
	}

	profile := false
	profileFlag := command.Flags().Lookup("profile")
	if profileFlag != nil {
		profile, _ = strconv.ParseBool(profileFlag.Value.String())
	}

	allowOther := false
	allowOtherFlag := command.Flags().Lookup("allow_other")
	if allowOtherFlag != nil {
		allowOther, _ = strconv.ParseBool(allowOtherFlag.Value.String())
	}

	childProcess := false
	childProcessFlag := command.Flags().Lookup(ChildProcessArgument)
	if childProcessFlag != nil {
		childProcess, _ = strconv.ParseBool(childProcessFlag.Value.String())
	}

	if len(logLevel) > 0 {
		lvl, err := log.ParseLevel(logLevel)
		if err != nil {
			lvl = log.InfoLevel
		}

		log.SetLevel(lvl)
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	helpFlag := command.Flags().Lookup("help")
	if helpFlag != nil {
		help, _ := strconv.ParseBool(helpFlag.Value.String())
		if help {
			PrintHelp(command)
			return nil, nil, false, nil // stop here
		}
	}

	versionFlag := command.Flags().Lookup("version")
	if versionFlag != nil {
		version, _ := strconv.ParseBool(versionFlag.Value.String())
		if version {
			PrintVersion(command)
			return nil, nil, false, nil // stop here
		}
	}

	readConfig := false
	var config *commons.Config

	stdinClosed := false
	configFlag := command.Flags().Lookup("config")
	if configFlag != nil {
		configPath := configFlag.Value.String()
		if len(configPath) > 0 {
			if configPath == "-" {
				// read from stdin
				stdinReader := bufio.NewReader(os.Stdin)
				yamlBytes, err := io.ReadAll(stdinReader)
				if err != nil {
					readErr := xerrors.Errorf("failed to read config from stdin: %w", err)
					logger.Errorf("%+v", readErr)
					return nil, nil, false, readErr // stop here
				}

				serverConfig, err := commons.NewConfigFromYAML(yamlBytes)
				if err != nil {
					logger.Errorf("%+v", err)
					return nil, nil, false, err // stop here
				}

				// overwrite config
				config = serverConfig
				readConfig = true
				stdinClosed = true
			} else {
				// read from a file
				if commons.IsYAMLFile(configPath) {
					// YAML file
					yamlBytes, err := os.ReadFile(configPath)
					if err != nil {
						readErr := xerrors.Errorf("failed to read config file %q: %w", configPath, err)
						logger.Errorf("%+v", readErr)
						return nil, nil, false, readErr // stop here
					}

					serverConfig, err := commons.NewConfigFromYAML(yamlBytes)
					if err != nil {
						logger.Errorf("%+v", err)
						return nil, nil, false, err // stop here
					}

					// overwrite config
					config = serverConfig
					readConfig = true
				} else {
					// icommands environment
					serverConfig, err := commons.LoadICommandsEnvironmentDir(configPath)
					if err != nil {
						logger.Errorf("%+v", err)
						return nil, nil, false, err // stop here
					}

					// overwrite config
					config = serverConfig
					readConfig = true
				}
			}
		}
	}

	// default config
	if !readConfig {
		config = commons.NewDefaultConfig()
	}

	if len(config.LogLevel) > 0 {
		lvl, err := log.ParseLevel(config.LogLevel)
		if err != nil {
			lvl = log.InfoLevel
		}

		log.SetLevel(lvl)
	}

	// prioritize command-line flag over config files
	if len(logLevel) > 0 {
		lvl, err := log.ParseLevel(logLevel)
		if err != nil {
			lvl = log.InfoLevel
		}

		log.SetLevel(lvl)
	}

	if debug {
		log.SetLevel(log.DebugLevel)
		config.Debug = true
	}

	if foreground {
		config.Foreground = true
	}

	if profile {
		config.Profile = true
	}

	if allowOther {
		config.AllowOther = true
	}

	config.ChildProcess = childProcess

	if config.Debug {
		log.SetLevel(log.DebugLevel)
	}

	instanceIdFlag := command.Flags().Lookup("instance_id")
	if instanceIdFlag != nil {
		instanceId := instanceIdFlag.Value.String()
		if len(instanceId) > 0 {
			config.InstanceID = instanceId
		}
	}

	logPathFlag := command.Flags().Lookup("log_path")
	if logPathFlag != nil {
		logPath := logPathFlag.Value.String()
		if len(logPath) > 0 {
			config.LogPath = logPath
		}
	}

	dataRootFlag := command.Flags().Lookup("data_root")
	if dataRootFlag != nil {
		dataRoot := dataRootFlag.Value.String()
		if len(dataRoot) > 0 {
			config.DataRootPath = dataRoot
		}

		if len(config.LogPath) == 0 {
			config.LogPath = config.GetLogFilePath()
		}
	}

	err := config.MakeLogDir()
	if err != nil {
		logger.Error(err)
		return nil, nil, false, err // stop here
	}

	var logWriter io.WriteCloser
	logFilePath := config.GetLogFilePath()
	if logFilePath == "-" || len(logFilePath) == 0 {
		log.SetOutput(os.Stderr)
	} else {
		parentLogWriter, parentLogFilePath := getLogWriterForParentProcess(logFilePath)
		logWriter = parentLogWriter

		// use multi output - to output to file and stdout
		mw := io.MultiWriter(os.Stderr, parentLogWriter)
		log.SetOutput(mw)

		logger.Infof("Logging to %q", parentLogFilePath)
	}

	hostFlag := command.Flags().Lookup("host")
	if hostFlag != nil {
		host := hostFlag.Value.String()
		if len(host) > 0 {
			config.Host = host
		}
	}

	portFlag := command.Flags().Lookup("port")
	if portFlag != nil {
		port, err := strconv.ParseInt(portFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input to int: %w", err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, err // stop here
		}

		if port > 0 {
			config.Port = int(port)
		}
	}

	zoneFlag := command.Flags().Lookup("zone")
	if zoneFlag != nil {
		zone := zoneFlag.Value.String()
		if len(zone) > 0 {
			config.Zone = zone
		}
	}

	proxyUserFlag := command.Flags().Lookup("proxy_user")
	if proxyUserFlag != nil {
		proxyUser := proxyUserFlag.Value.String()
		if len(proxyUser) > 0 {
			config.ProxyUser = proxyUser
		}
	}

	userFlag := command.Flags().Lookup("user")
	if userFlag != nil {
		user := userFlag.Value.String()
		if len(user) > 0 {
			config.ProxyUser = user
		}
	}

	clientUserFlag := command.Flags().Lookup("client_user")
	if clientUserFlag != nil {
		clientUser := clientUserFlag.Value.String()
		if len(clientUser) > 0 {
			config.ClientUser = clientUser
		}
	}

	passwordFlag := command.Flags().Lookup("password")
	if passwordFlag != nil {
		password := passwordFlag.Value.String()
		if len(password) > 0 {
			config.Password = password
		}
	}

	resourceFlag := command.Flags().Lookup("resource")
	if resourceFlag != nil {
		resource := resourceFlag.Value.String()
		if len(resource) > 0 {
			config.Resource = resource
		}
	}

	pathMappingFileFlag := command.Flags().Lookup("path_mapping_file")
	if pathMappingFileFlag != nil {
		pathMappingFile := pathMappingFileFlag.Value.String()
		if len(pathMappingFile) > 0 {
			// YAML file
			yamlBytes, err := os.ReadFile(pathMappingFile)
			if err != nil {
				readErr := xerrors.Errorf("failed to read path mapping from file %q: %w", pathMappingFile, err)
				logger.Errorf("%+v", readErr)
				return nil, logWriter, false, readErr // stop here
			}

			pathMappings := []irodsfs_common_vpath.VPathMapping{}
			err = yaml.Unmarshal(yamlBytes, &pathMappings)
			if err != nil {
				yamlErr := xerrors.Errorf("failed to unmarshal yaml into path mapping: %w", err)
				logger.Errorf("%+v", yamlErr)
				return nil, logWriter, false, yamlErr // stop here
			}

			config.PathMappings = pathMappings
		}
	}

	readaheadFlag := command.Flags().Lookup("readahead")
	if readaheadFlag != nil {
		readahead, err := strconv.ParseInt(readaheadFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to int64: %w", readaheadFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if readahead > 0 {
			config.ReadAheadMax = int(readahead)
		}
	}

	connectionMaxFlag := command.Flags().Lookup("connection_max")
	if connectionMaxFlag != nil {
		connectionMax, err := strconv.ParseInt(connectionMaxFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to int64: %w", connectionMaxFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if connectionMax > 0 {
			config.ConnectionMax = int(connectionMax)
		}
	}

	operationTimeoutFlag := command.Flags().Lookup("operation_timeout")
	if operationTimeoutFlag != nil {
		operationTimeout, err := time.ParseDuration(operationTimeoutFlag.Value.String())
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to duration: %w", operationTimeoutFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		config.OperationTimeout = irodsfs_common_utils.Duration(operationTimeout)
	}

	connectionIdleTimeoutFlag := command.Flags().Lookup("connection_idle_timeout")
	if connectionIdleTimeoutFlag != nil {
		connectionIdleTimeout, err := time.ParseDuration(connectionIdleTimeoutFlag.Value.String())
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to duration: %w", connectionIdleTimeoutFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		config.ConnectionIdleTimeout = irodsfs_common_utils.Duration(connectionIdleTimeout)
	}

	metadataCacheTimeoutFlag := command.Flags().Lookup("metadata_cache_timeout")
	if metadataCacheTimeoutFlag != nil {
		metadataCacheTimeout, err := time.ParseDuration(metadataCacheTimeoutFlag.Value.String())
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to duration: %w", metadataCacheTimeoutFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		config.MetadataCacheTimeout = irodsfs_common_utils.Duration(metadataCacheTimeout)
	}

	metadataCacheCleanupTimeFlag := command.Flags().Lookup("metadata_cache_timeout")
	if metadataCacheCleanupTimeFlag != nil {
		metadataCacheCleanupTime, err := time.ParseDuration(metadataCacheCleanupTimeFlag.Value.String())
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to duration: %w", metadataCacheCleanupTimeFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		config.MetadataCacheCleanupTime = irodsfs_common_utils.Duration(metadataCacheCleanupTime)
	}

	noPermissionCheckFlag := command.Flags().Lookup("no_permission_check")
	if noPermissionCheckFlag != nil {
		noPermissionCheck, _ := strconv.ParseBool(noPermissionCheckFlag.Value.String())
		config.NoPermissionCheck = noPermissionCheck
	}

	noSetXattrFlag := command.Flags().Lookup("no_set_xattr")
	if noSetXattrFlag != nil {
		noSetXattr, _ := strconv.ParseBool(noSetXattrFlag.Value.String())
		config.NoSetXattr = noSetXattr
	}

	noTransactionFlag := command.Flags().Lookup("no_transaction")
	if noTransactionFlag != nil {
		noTransaction, _ := strconv.ParseBool(noTransactionFlag.Value.String())
		config.StartNewTransaction = !noTransaction
	}

	uidFlag := command.Flags().Lookup("uid")
	if uidFlag != nil {
		uid, err := strconv.ParseInt(uidFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to int: %w", uidFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if uid > 0 {
			config.UID = int(uid)
		}
	}

	gidFlag := command.Flags().Lookup("gid")
	if gidFlag != nil {
		gid, err := strconv.ParseInt(gidFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to int: %w", gidFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if gid > 0 {
			config.GID = int(gid)
		}
	}

	sysUserFlag := command.Flags().Lookup("sys_user")
	if sysUserFlag != nil {
		sysUser := sysUserFlag.Value.String()
		if len(sysUser) > 0 {
			config.SystemUser = sysUser
		}
	}

	fuseOptionsFlag := command.Flags().Lookup("fuse_option")
	if fuseOptionsFlag != nil {
		fuseOptionsString := fuseOptionsFlag.Value.String()
		fuseOptionsString = strings.Trim(fuseOptionsString, "[]")
		if len(fuseOptionsString) > 0 {
			fuseOptionsStringArray := strings.Split(fuseOptionsString, ",")
			config.FuseOptions = fuseOptionsStringArray
		}
	}

	profilePortFlag := command.Flags().Lookup("profile_port")
	if profilePortFlag != nil {
		profilePort, err := strconv.ParseInt(profilePortFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to int: %w", profilePortFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if profilePort > 0 {
			config.ProfileServicePort = int(profilePort)
		}
	}

	poolEndpointFlag := command.Flags().Lookup("pool_endpoint")
	if poolEndpointFlag != nil {
		poolEndpoint := poolEndpointFlag.Value.String()
		if len(poolEndpoint) > 0 {
			config.PoolEndpoint = poolEndpoint
		}
	}

	monitorUrlFlag := command.Flags().Lookup("monitor_url")
	if monitorUrlFlag != nil {
		monitorUrl := monitorUrlFlag.Value.String()
		if len(monitorUrl) > 0 {
			config.MonitorURL = monitorUrl
		}
	}

	// positional arguments
	mountPath := ""
	if len(args) == 0 {
		PrintHelp(command)
		return nil, logWriter, false, xerrors.Errorf("mount point is not provided") // stop here
	}

	mountPath = args[len(args)-1]

	if len(args) == 2 {
		// first arg may be shorthand form of config
		// the first argument contains irods://HOST:PORT/ZONE/inputPath...
		err := updateConfigFromIrodsUrl(args[0], config)
		if err != nil {
			logger.Errorf("%+v", err)
			return nil, logWriter, false, err // stop here
		}
	}

	if !stdinClosed {
		err = inputMissingParams(config)
		if err != nil {
			logger.Errorf("%+v", err)
			return nil, logWriter, false, err // stop here
		}
	}

	// the second argument is local directory that irodsfs will be mounted
	mountpoint, err := filepath.Abs(mountPath)
	if err != nil {
		absErr := xerrors.Errorf("failed to get abs path for %q: %w", mountPath, err)
		logger.Errorf("%+v", absErr)
		return nil, logWriter, false, absErr // stop here
	}

	config.MountPath = mountpoint

	err = config.CorrectSystemUser()
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, logWriter, false, err // stop here
	}

	err = config.Validate()
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, logWriter, false, err // stop here
	}

	return config, logWriter, true, nil // continue
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

func getLogWriterForParentProcess(logPath string) (io.WriteCloser, string) {
	logFilePath := fmt.Sprintf("%s.parent", logPath)
	return &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    50, // 50MB
		MaxBackups: 5,
		MaxAge:     30, // 30 days
		Compress:   false,
	}, logFilePath
}

func getLogWriterForChildProcess(logPath string) (io.WriteCloser, string) {
	logFilePath := fmt.Sprintf("%s.child", logPath)
	return &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    50, // 50MB
		MaxBackups: 5,
		MaxAge:     30, // 30 days
		Compress:   false,
	}, logFilePath
}

// inputMissingParams gets user inputs for parameters missing, such as username and password
func inputMissingParams(config *commons.Config) error {
	if len(config.ProxyUser) == 0 {
		fmt.Print("Username: ")
		fmt.Scanln(&config.ProxyUser)
	}

	if len(config.ClientUser) == 0 {
		config.ClientUser = config.ProxyUser
	}

	if len(config.Password) == 0 {
		fmt.Print("Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Print("\n")
		if err != nil {
			return xerrors.Errorf("failed to read password: %w", err)
		}

		config.Password = string(bytePassword)
	}

	return nil
}
