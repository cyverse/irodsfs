package commons

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cyverse/irodsfs/commons"
	"golang.org/x/xerrors"
	"gopkg.in/natefinch/lumberjack.v2"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func SetCommonFlags(command *cobra.Command) {
	command.Flags().BoolP("version", "v", false, "Print version")
	command.Flags().BoolP("help", "h", false, "Print help")
	command.Flags().BoolP("debug", "d", false, "Enable debug mode")
	command.Flags().String("log_level", "", "Set log level (default is INFO)")
	command.Flags().Bool("profile", false, "Enable profiling")
	command.Flags().BoolP("foreground", "f", false, "Run in foreground")
	command.Flags().Bool("allow_other", false, "Allow access from other users")
	command.Flags().Bool("readonly", false, "Set read-only")

	command.Flags().StringP("config", "c", commons.GetDefaultIRODSConfigPath(), "Set config file or directory")
	command.Flags().String("instance_id", "", "Set instance ID")
	command.Flags().String("log_path", "", "Set log file path")

	command.Flags().String("host", "", "Set iRODS host")
	command.Flags().Int("port", 1247, "Set iRODS port")
	command.Flags().String("zone", "", "Set iRODS zone name")
	command.Flags().String("client_zone", "", "Set client iRODS zone name")
	command.Flags().StringP("username", "u", "", "Set iRODS username")
	command.Flags().String("client_username", "", "Set iRODS client username")
	command.Flags().StringP("password", "p", "", "Set iRODS password")
	command.Flags().StringP("resource", "R", "", "Set default iRODS resource")

	command.Flags().Int("read_ahead_max", 0, "Set read-ahead size")
	command.Flags().Int("read_write_max", 0, "Set read-write size")
	command.Flags().Bool("no_permission_check", false, "Disable permission check for performance")
	command.Flags().Bool("no_set_xattr", false, "Disable set xattr")
	command.Flags().Bool("no_transaction", false, "Disable transaction for performance")

	command.Flags().Int("uid", os.Geteuid(), "Set UID of file/directory owner")
	command.Flags().Int("gid", os.Getegid(), "Set GID of file/directory owner")
	command.Flags().String("sys_user", "", "Set System User of file/directory owner")

	command.Flags().StringArrayP("fuse_option", "o", []string{}, "Set FUSE options")

	command.Flags().String("data_root", "", "Set data root dir path")

	command.Flags().Int("profile_port", 11021, "Set profile service port")
	command.Flags().String("pool_endpoint", "", "Set iRODS FUSE Lite Pool Service endpoint")

	command.Flags().Bool("child_process", false, "")
	command.Flags().MarkHidden("child_process")

	command.Flags().Bool("watchdog_process", false, "")
	command.Flags().MarkHidden("watchdog_process")
}

func IsChildProcess(command *cobra.Command) bool {
	childProcess := false
	childProcessFlag := command.Flags().Lookup("child_process")
	if childProcessFlag != nil && childProcessFlag.Changed {
		childProcess, _ = strconv.ParseBool(childProcessFlag.Value.String())
	}

	return childProcess
}

func IsWatchdogProcess(command *cobra.Command) bool {
	watchdogProcess := false
	watchdogProcessFlag := command.Flags().Lookup("watchdog_process")
	if watchdogProcessFlag != nil && watchdogProcessFlag.Changed {
		watchdogProcess, _ = strconv.ParseBool(watchdogProcessFlag.Value.String())
	}

	return watchdogProcess
}

func ProcessCommonFlags(command *cobra.Command, args []string) (*commons.Config, io.WriteCloser, bool, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "ProcessCommonFlags",
	})

	logLevel := ""
	logLevelFlag := command.Flags().Lookup("log_level")
	if logLevelFlag != nil && logLevelFlag.Changed {
		logLevelStr := logLevelFlag.Value.String()
		logLevel = logLevelStr
	}

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

	profile := false
	profileFlag := command.Flags().Lookup("profile")
	if profileFlag != nil && profileFlag.Changed {
		profile, _ = strconv.ParseBool(profileFlag.Value.String())
	}

	allowOther := false
	allowOtherFlag := command.Flags().Lookup("allow_other")
	if allowOtherFlag != nil && allowOtherFlag.Changed {
		allowOther, _ = strconv.ParseBool(allowOtherFlag.Value.String())
	}

	readOnly := false
	readOnlyFlag := command.Flags().Lookup("readonly")
	if readOnlyFlag != nil {
		readOnly, _ = strconv.ParseBool(readOnlyFlag.Value.String())
	}

	childProcess := false
	childProcessFlag := command.Flags().Lookup("child_process")
	if childProcessFlag != nil && childProcessFlag.Changed {
		childProcess, _ = strconv.ParseBool(childProcessFlag.Value.String())
	}

	watchdogProcess := false
	watchdogProcessFlag := command.Flags().Lookup("watchdog_process")
	if watchdogProcessFlag != nil && watchdogProcessFlag.Changed {
		watchdogProcess, _ = strconv.ParseBool(watchdogProcessFlag.Value.String())
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
	if helpFlag != nil && helpFlag.Changed {
		help, _ := strconv.ParseBool(helpFlag.Value.String())
		if help {
			PrintHelp(command)
			return nil, nil, false, nil // stop here
		}
	}

	versionFlag := command.Flags().Lookup("version")
	if versionFlag != nil && versionFlag.Changed {
		version, _ := strconv.ParseBool(versionFlag.Value.String())
		if version {
			PrintVersion(command)
			return nil, nil, false, nil // stop here
		}
	}

	configFilePath := commons.GetDefaultIRODSConfigPath()

	// find config file location from env
	if irodsEnvironmentFileEnvVal, ok := os.LookupEnv(commons.IRODSEnvironmentFileEnvKey); ok {
		if len(irodsEnvironmentFileEnvVal) > 0 {
			configFilePath = irodsEnvironmentFileEnvVal
		}
	}

	configFlag := command.Flags().Lookup("config")
	if configFlag != nil && configFlag.Changed {
		configPath := configFlag.Value.String()
		if len(configPath) > 0 {
			// user defined config file
			configFilePath = configPath
		}
	}

	// default config
	config := commons.NewDefaultConfig()
	stdinClosed := false

	if configFilePath == "-" {
		// read from stdin
		stdinReader := bufio.NewReader(os.Stdin)
		yamlBytes, err := io.ReadAll(stdinReader)
		if err != nil {
			readErr := xerrors.Errorf("failed to read config from stdin: %w", err)
			logger.Errorf("%+v", readErr)
			return nil, nil, false, readErr // stop here
		}

		newConfig, err := commons.NewConfigFromYAML(config, yamlBytes)
		if err != nil {
			logger.Errorf("%+v", err)
			return nil, nil, false, err // stop here
		}

		// overwrite config
		config = newConfig
		stdinClosed = true
	} else {
		// read from a file
		newConfig, err := commons.NewConfigFromFile(config, configFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Debugf("config file not found at %s", configFilePath)
				// use default
			} else {
				logger.Errorf("%+v", err)
				return nil, nil, false, err // stop here
			}
		} else {
			// overwrite config
			config = newConfig
		}
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

	if readOnly {
		config.Readonly = true
	}

	config.ChildProcess = childProcess
	config.WatchdogProcess = watchdogProcess

	if config.Debug {
		log.SetLevel(log.DebugLevel)
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
	if hostFlag != nil && hostFlag.Changed {
		host := hostFlag.Value.String()
		if len(host) > 0 {
			config.Host = host
		}
	}

	portFlag := command.Flags().Lookup("port")
	if portFlag != nil && portFlag.Changed {
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
	if zoneFlag != nil && zoneFlag.Changed {
		zone := zoneFlag.Value.String()
		if len(zone) > 0 {
			config.ZoneName = zone
		}
	}

	clientZoneFlag := command.Flags().Lookup("client_zone")
	if clientZoneFlag != nil && clientZoneFlag.Changed {
		clientZone := clientZoneFlag.Value.String()
		if len(clientZone) > 0 {
			config.ClientZoneName = clientZone
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

	resourceFlag := command.Flags().Lookup("resource")
	if resourceFlag != nil && resourceFlag.Changed {
		resource := resourceFlag.Value.String()
		if len(resource) > 0 {
			config.DefaultResource = resource
		}
	}

	readAheadMaxFlag := command.Flags().Lookup("read_ahead_max")
	if readAheadMaxFlag != nil && readAheadMaxFlag.Changed {
		readAheadMax, err := strconv.ParseInt(readAheadMaxFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to int64: %w", readAheadMaxFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if readAheadMax > 0 {
			config.ReadAheadMax = int(readAheadMax)
		}
	}

	readWriteMaxFlag := command.Flags().Lookup("read_write_max")
	if readWriteMaxFlag != nil && readWriteMaxFlag.Changed {
		readWriteMax, err := strconv.ParseInt(readWriteMaxFlag.Value.String(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to convert input %q to int64: %w", readWriteMaxFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if readWriteMax > 0 {
			config.ReadWriteMax = int(readWriteMax)
		}
	}

	noPermissionCheckFlag := command.Flags().Lookup("no_permission_check")
	if noPermissionCheckFlag != nil && noPermissionCheckFlag.Changed {
		noPermissionCheck, _ := strconv.ParseBool(noPermissionCheckFlag.Value.String())
		config.NoPermissionCheck = noPermissionCheck
	}

	noSetXattrFlag := command.Flags().Lookup("no_set_xattr")
	if noSetXattrFlag != nil && noSetXattrFlag.Changed {
		noSetXattr, _ := strconv.ParseBool(noSetXattrFlag.Value.String())
		config.NoSetXattr = noSetXattr
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
			parseErr := xerrors.Errorf("failed to convert input %q to int: %w", uidFlag.Value.String(), err)
			logger.Errorf("%+v", parseErr)
			return nil, logWriter, false, parseErr // stop here
		}

		if uid > 0 {
			config.UID = int(uid)
		}
	}

	gidFlag := command.Flags().Lookup("gid")
	if gidFlag != nil && gidFlag.Changed {
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

	profilePortFlag := command.Flags().Lookup("profile_port")
	if profilePortFlag != nil && profilePortFlag.Changed {
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
		return nil, logWriter, false, xerrors.Errorf("mount point is not provided") // stop here
	}

	mountPath = args[len(args)-1]

	if len(args) == 2 {
		// first arg may be shorthand form of config
		// the first argument contains irods://HOST:PORT/ZONE/inputPath...
		err := config.FromIRODSUrl(args[0])
		if err != nil {
			logger.Errorf("%+v", err)
			return nil, logWriter, false, err // stop here
		}
	}

	config.FixAuthConfiguration()

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

	err = config.FixSystemUserConfiguration()
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, logWriter, false, err // stop here
	}
	config.FixPathMappings()

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

	commons.Println(info)
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

func getLogWriterForWatchdogProcess(logPath string) (io.WriteCloser, string) {
	logFilePath := fmt.Sprintf("%s.watchdog", logPath)
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
	if len(config.Username) == 0 {
		config.Username = commons.Input("Username: ")
	}

	if len(config.ClientUsername) == 0 {
		config.ClientUsername = config.Username
	}

	if len(config.Password) == 0 {
		config.Password = commons.InputPassword("iRODS Password")
	}

	config.FixAuthConfiguration()

	return nil
}
