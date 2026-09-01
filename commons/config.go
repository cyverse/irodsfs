package commons

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/cockroachdb/errors"
	irodsclient_config "github.com/cyverse/go-irodsclient/config"
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsclient_util "github.com/cyverse/go-irodsclient/irods/util"
	"github.com/cyverse/irodsfs-common/irods/vpath"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert/yaml"
	"gopkg.in/natefinch/lumberjack.v2"
)

// GetDefaultInstanceID returns default instance id
func GetDefaultInstanceID() string {
	return xid.New().String()
}

// GetDefaultDataRootDirPath returns default data root path
func GetDefaultDataRootDirPath() string {
	dirPath, err := os.Getwd()
	if err != nil {
		return DataRootPathFallback
	}
	return dirPath
}

// GetDefaultIRODSConfigPath returns default config path
func GetDefaultIRODSConfigPath() string {
	irodsConfigPath, err := irodsclient_util.ExpandLocalHomeDir("~/.irods")
	if err != nil {
		return ""
	}

	return irodsConfigPath
}

// Config holds the parameters list which can be configured
type Config struct {
	irodsclient_config.Config // irods config

	MountPath    string `json:"mount_path,omitempty" yaml:"mount_path,omitempty"`
	DataRootPath string `json:"data_root_path,omitempty" yaml:"data_root_path,omitempty"`

	PathMappings []vpath.VPathMapping `json:"path_mappings,omitempty" yaml:"path_mappings,omitempty"`
	ReadAheadMax int                  `json:"read_ahead_max,omitempty" yaml:"read_ahead_max,omitempty"`
	ReadWriteMax int                  `json:"read_write_max,omitempty" yaml:"read_write_max,omitempty"`
	Readonly     bool                 `json:"readonly,omitempty" yaml:"readonly,omitempty"`
	FuseOptions  []string             `json:"fuse_options,omitempty" yaml:"fuse_options,omitempty"`

	UID        int    `json:"uid,omitempty" yaml:"uid,omitempty"`
	GID        int    `json:"gid,omitempty" yaml:"gid,omitempty"`
	SystemUser string `json:"system_user,omitempty" yaml:"system_user,omitempty"`

	MetadataConnection irodsclient_fs.ConnectionConfig `json:"metadata_connection,omitempty" yaml:"metadata_connection,omitempty"`
	IOConnection       irodsclient_fs.ConnectionConfig `json:"io_connection,omitempty" yaml:"io_connection,omitempty"`
	Cache              irodsclient_fs.CacheConfig      `json:"cache,omitempty" yaml:"cache,omitempty"`

	PoolEndpoint string `json:"pool_endpoint,omitempty" yaml:"pool_endpoint,omitempty"`

	Foreground bool `json:"foreground,omitempty" yaml:"foreground,omitempty"`
	Debug      bool `json:"debug,omitempty" yaml:"debug,omitempty"`

	InstanceID  string `json:"instanceid,omitempty" yaml:"instanceid,omitempty"`
	LogPath     string `json:"log_path,omitempty" yaml:"log_path,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	return &Config{
		Config: *irodsclient_config.GetDefaultConfig(),

		MountPath:    "", // leave it empty
		DataRootPath: GetDefaultDataRootDirPath(),

		PathMappings: []vpath.VPathMapping{},
		ReadAheadMax: ReadAheadMaxDefault,
		ReadWriteMax: ReadWriteMaxDefault,
		Readonly:     false,
		FuseOptions:  []string{},

		UID:        -1,
		GID:        -1,
		SystemUser: "",

		MetadataConnection: irodsclient_fs.NewDefaultMetadataConnectionConfig(),
		IOConnection:       irodsclient_fs.NewDefaultIOConnectionConfig(),
		Cache:              irodsclient_fs.NewDefaultCacheConfig(),

		PoolEndpoint: "",

		Foreground: false,
		Debug:      false,

		InstanceID:  GetDefaultInstanceID(),
		LogPath:     "", // use default
		Description: "",
	}
}

// NewConfigFromFile creates Config from file
func NewConfigFromFile(config *Config, filePath string) (*Config, error) {
	st, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}

		return nil, errors.Wrapf(err, "failed to stat file %q", filePath)
	}

	if st.IsDir() {
		return NewConfigFromICommandsEnvDir(config, filePath)
	}

	dataBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read file %q", filePath)
	}

	format := DetectFormat(dataBytes)
	switch format {
	case FormatJSON:
		return NewConfigFromJSONFile(config, filePath)
	case FormatYAML:
		return NewConfigFromYAMLFile(config, filePath)
	default:
		return nil, errors.New("unknown file format")
	}
}

// NewConfigFromYAMLFile creates Config from YAML
func NewConfigFromYAMLFile(config *Config, yamlPath string) (*Config, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}

	yamlBytes, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read YAML file %q", yamlPath)
	}

	err = yaml.Unmarshal(yamlBytes, &cfg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal YAML file %q to config", yamlPath)
	}

	// load icommands environment
	iCommandsEnvMgr, err := irodsclient_config.NewICommandsEnvironmentManager()
	if err != nil {
		return nil, err
	}

	err = iCommandsEnvMgr.SetEnvironmentFilePath(yamlPath)
	if err != nil {
		return nil, err
	}

	err = iCommandsEnvMgr.Load()
	if err != nil {
		return nil, err
	}

	// overwrite
	cfg.Config = *iCommandsEnvMgr.Environment

	return &cfg, nil
}

// NewConfigFromJSONFile creates Config from JSON
func NewConfigFromJSONFile(config *Config, jsonPath string) (*Config, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}

	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read JSON file %q", jsonPath)
	}

	err = json.Unmarshal(jsonBytes, &cfg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal JSON file %q to config", jsonPath)
	}

	// load icommands environment
	iCommandsEnvMgr, err := irodsclient_config.NewICommandsEnvironmentManager()
	if err != nil {
		return nil, err
	}

	err = iCommandsEnvMgr.SetEnvironmentFilePath(jsonPath)
	if err != nil {
		return nil, err
	}

	err = iCommandsEnvMgr.Load()
	if err != nil {
		return nil, err
	}

	// overwrite
	cfg.Config = *iCommandsEnvMgr.Environment

	return &cfg, nil
}

// NewConfigFromICommandsEnvDir creates Config from icommands environment dir (e.g., ~/.irods)
func NewConfigFromICommandsEnvDir(config *Config, dirPath string) (*Config, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}

	// load icommands environment
	iCommandsEnvMgr, err := irodsclient_config.NewICommandsEnvironmentManager()
	if err != nil {
		return nil, err
	}

	err = iCommandsEnvMgr.SetEnvironmentDirPath(dirPath)
	if err != nil {
		return nil, err
	}

	err = iCommandsEnvMgr.Load()
	if err != nil {
		return nil, err
	}

	// overwrite
	cfg.Config = *iCommandsEnvMgr.Environment

	return &cfg, nil
}

func NewConfigFromStdin(config *Config, bytes []byte) (*Config, error) {
	format := DetectFormat(bytes)
	switch format {
	case FormatJSON:
		return NewConfigFromJSON(config, bytes)
	case FormatYAML:
		return NewConfigFromYAML(config, bytes)
	default:
		return nil, errors.Newf("unknown data format")
	}
}

// NewConfigFromYAML creates Config from YAML
func NewConfigFromYAML(config *Config, yamlBytes []byte) (*Config, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}

	err := yaml.Unmarshal(yamlBytes, &cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal YAML to config")
	}

	// load icommands environment
	if len(cfg.AuthenticationFile) > 0 {
		if irodsclient_util.ExistLocalFile(cfg.AuthenticationFile) {
			obfuscator := irodsclient_config.NewPasswordObfuscator()
			passwordBytes, err := obfuscator.DecodeFile(cfg.AuthenticationFile)
			if err != nil {
				// continue
			} else {
				authScheme := irodsclient_types.GetAuthScheme(cfg.AuthenticationScheme)
				if authScheme.IsPAM() {
					cfg.Password = ""
					cfg.PAMToken = string(passwordBytes)
				} else {
					cfg.Password = string(passwordBytes)
					cfg.PAMToken = ""
				}
			}
		}
	}

	return &cfg, nil
}

// NewConfigFromJSON creates Config from JSON
func NewConfigFromJSON(config *Config, jsonBytes []byte) (*Config, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}

	err := json.Unmarshal(jsonBytes, &cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal YAML to config")
	}

	// load icommands environment
	if len(cfg.AuthenticationFile) > 0 {
		if irodsclient_util.ExistLocalFile(cfg.AuthenticationFile) {
			obfuscator := irodsclient_config.NewPasswordObfuscator()
			passwordBytes, err := obfuscator.DecodeFile(cfg.AuthenticationFile)
			if err != nil {
				// continue
			} else {
				authScheme := irodsclient_types.GetAuthScheme(cfg.AuthenticationScheme)
				if authScheme.IsPAM() {
					cfg.Password = ""
					cfg.PAMToken = string(passwordBytes)
				} else {
					cfg.Password = string(passwordBytes)
					cfg.PAMToken = ""
				}
			}
		}
	}

	return &cfg, nil
}

// FixSystemUserConfiguration fixes system user configuration
func (config *Config) FixSystemUserConfiguration() error {
	systemUser, uid, gid, err := CorrectSystemUser(config.SystemUser, config.UID, config.GID)
	if err != nil {
		return err
	}

	config.SystemUser = systemUser
	config.UID = uid
	config.GID = gid
	return nil
}

// FixPathMappings fixes path mappings
func (config *Config) FixPathMappings() {
	if len(config.PathMappings) == 0 {
		if len(config.CurrentWorkingDir) > 0 {
			config.PathMappings = []vpath.VPathMapping{
				{
					IRODSPath:           config.CurrentWorkingDir,
					MappingPath:         "/",
					ResourceType:        vpath.VPathMappingDirectory,
					ReadOnly:            false,
					CreateDir:           false,
					IgnoreNotExistError: false,
				},
			}
		} else if len(config.Home) > 0 {
			config.PathMappings = []vpath.VPathMapping{
				{
					IRODSPath:           config.Home,
					MappingPath:         "/",
					ResourceType:        vpath.VPathMappingDirectory,
					ReadOnly:            false,
					CreateDir:           false,
					IgnoreNotExistError: false,
				},
			}
		} else {
			iRODSHomePath := fmt.Sprintf("/%s/home/%s", config.ClientZoneName, config.ClientUsername)
			config.PathMappings = []vpath.VPathMapping{
				{
					IRODSPath:           iRODSHomePath,
					MappingPath:         "/",
					ResourceType:        vpath.VPathMappingDirectory,
					ReadOnly:            false,
					CreateDir:           false,
					IgnoreNotExistError: false,
				},
			}
		}
	}

	// fix readonly
	if config.Readonly {
		for idx := range config.PathMappings {
			config.PathMappings[idx].ReadOnly = true
		}
	}
}

// GetLogFilePath returns log file path
func (config *Config) GetLogFilePath() string {
	if len(config.LogPath) > 0 {
		return config.LogPath
	}

	// default
	logFilename := fmt.Sprintf("irodsfs-%s.log", config.InstanceID)
	return path.Join(config.DataRootPath, logFilename)
}

func (config *Config) GetDataRootPath() string {
	return config.DataRootPath
}

// MakeLogDir makes a log dir required
func (config *Config) MakeLogDir() error {
	logFilePath := config.GetLogFilePath()
	if logFilePath == "-" {
		return nil
	}

	return config.makeDir(filepath.Dir(logFilePath))
}

// MakeWorkDirs makes dirs required
func (config *Config) MakeWorkDirs() error {
	dataRootPath := config.GetDataRootPath()
	err := config.makeDir(dataRootPath)
	if err != nil {
		return err
	}

	return nil
}

// makeDir makes a dir for use
func (config *Config) makeDir(path string) error {
	if len(path) == 0 {
		return errors.New("failed to create a dir with empty path")
	}

	dirInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// make
			mkdirErr := os.MkdirAll(path, 0775)
			if mkdirErr != nil {
				return errors.Wrapf(mkdirErr, "making a dir %q error", path)
			}

			return nil
		}

		return errors.Wrapf(err, "stating a dir %q error", path)
	}

	if !dirInfo.IsDir() {
		return errors.Newf("a file %q exist, not a directory", path)
	}

	dirPerm := dirInfo.Mode().Perm()
	if dirPerm&0200 != 0200 {
		return errors.Newf("a dir %q exist, but does not have the write permission", path)
	}

	return nil
}

// Validate validates configuration
func (config *Config) Validate() error {
	err := config.Config.ToIRODSAccount().Validate()
	if err != nil {
		return err
	}

	if len(config.MountPath) == 0 {
		return errors.New("mount path must be given")
	}

	mountDirInfo, err := os.Stat(config.MountPath)
	if err != nil {
		return errors.Wrapf(err, "mountpoint %q error", config.MountPath)
	}

	if !mountDirInfo.IsDir() {
		return errors.Newf("mountpoint %q must be a directory", config.MountPath)
	}

	mountDirPerm := mountDirInfo.Mode().Perm()
	if mountDirPerm&0200 != 0200 {
		return errors.Newf("mountpoint %q must have write permission", config.MountPath)
	}

	if len(config.DataRootPath) == 0 {
		return errors.New("data root dir must be given")
	}

	err = vpath.ValidateVPathMappings(config.PathMappings)
	if err != nil {
		return errors.Wrap(err, "invalid path mappings")
	}

	if config.ReadAheadMax < 0 {
		return errors.New("read-ahead max must be equal or greater than 0")
	}

	if config.ReadWriteMax < 0 {
		return errors.New("read write max must be equal or greater than 0")
	}

	if config.UID < 0 {
		return errors.Newf("invalid UID %d", config.UID)
	}

	if config.GID < 0 {
		return errors.Newf("invalid GID %d", config.GID)
	}

	if config.MetadataConnection.MaxNumber < 1 {
		return errors.New("metadata connection max must be equal or greater than 1")
	}

	if config.IOConnection.MaxNumber < 1 {
		return errors.New("io connection max must be equal or greater than 1")
	}

	if len(config.PoolEndpoint) > 0 {
		_, _, err := ParsePoolServiceEndpoint(config.PoolEndpoint)
		if err != nil {
			return err
		}
	}

	return nil
}

// FromIRODSUrl reads info from inputURL and updates config
func (config *Config) FromIRODSUrl(inputURL string) error {
	// the inputURL contains irods://HOST:PORT/ZONE/inputPath...
	u, err := ParseIRODSUrl(inputURL)
	if err != nil {
		return err
	}

	if len(u.Host) > 0 {
		config.Host = u.Host
	}

	if u.Port > 0 {
		config.Port = u.Port
	}

	if len(u.User) > 0 {
		config.Username = u.User
	}

	if len(u.Password) > 0 {
		config.Password = u.Password
	}

	if len(u.Zone) > 0 {
		config.ZoneName = u.Zone
	}

	if len(u.Path) > 0 {
		config.PathMappings = []vpath.VPathMapping{
			{
				IRODSPath:           u.Path,
				MappingPath:         "/",
				ResourceType:        vpath.VPathMappingDirectory,
				ReadOnly:            false,
				CreateDir:           false,
				IgnoreNotExistError: false,
			},
		}
	}

	return nil
}

// MultiWriteCloser writes to multiple writers and closes the ones that implement io.Closer.
type MultiWriteCloser struct {
	writers []io.Writer
}

func NewMultiWriteCloser(writers ...io.Writer) *MultiWriteCloser {
	return &MultiWriteCloser{writers: writers}
}

func (mw *MultiWriteCloser) Write(p []byte) (n int, err error) {
	for _, w := range mw.writers {
		n, err = w.Write(p)
		if err != nil {
			return n, err
		}
	}
	return len(p), nil
}

func (mw *MultiWriteCloser) Close() error {
	var firstErr error
	for _, w := range mw.writers {
		if closer, ok := w.(io.Closer); ok {
			if err := closer.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (config *Config) GetLogWriter(foregroundProcess bool) (io.WriteCloser, error) {
	logFilePath := config.GetLogFilePath()
	if logFilePath == "-" || len(logFilePath) == 0 {
		return os.Stderr, nil
	}

	err := config.MakeLogDir()
	if err != nil {
		return nil, err
	}

	if foregroundProcess {
		fileWriter := getLogWriterForForegroundProcess(logFilePath)
		return NewMultiWriteCloser(os.Stderr, fileWriter), nil
	}

	daemonWriter := getLogWriterForDaemonProcess(logFilePath)
	return daemonWriter, nil
}

func getLogWriterForForegroundProcess(logPath string) io.WriteCloser {
	logFilePath := fmt.Sprintf("%s.fg", logPath)
	return &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    50, // 50MB
		MaxBackups: 5,
		MaxAge:     30, // 30 days
		Compress:   false,
	}
}

func getLogWriterForDaemonProcess(logPath string) io.WriteCloser {
	logFilePath := fmt.Sprintf("%s", logPath)
	return &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    50, // 50MB
		MaxBackups: 1000,
		MaxAge:     365, // 365 days
		Compress:   false,
	}
}
