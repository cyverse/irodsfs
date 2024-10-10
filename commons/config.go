package commons

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	irodsclient_config "github.com/cyverse/go-irodsclient/config"
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsclient_util "github.com/cyverse/go-irodsclient/irods/util"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	"golang.org/x/xerrors"

	"github.com/cyverse/irodsfs/utils"
	"github.com/rs/xid"
	yaml "gopkg.in/yaml.v2"
)

// GetDefaultInstanceID returns default instance id
func GetDefaultInstanceID() string {
	return xid.New().String()
}

// GetDefaultDataRootDirPath returns default data root path
func GetDefaultDataRootDirPath() string {
	dirPath, err := os.Getwd()
	if err != nil {
		return "/var/lib/irodsfs"
	}
	return dirPath
}

// GetDefaultIRODSConfigPath returns default config path
func GetDefaultIRODSConfigPath() string {
	irodsConfigPath, err := ExpandHomeDir("~/.irods")
	if err != nil {
		return ""
	}

	return irodsConfigPath
}

// Config holds the parameters list which can be configured
type Config struct {
	irodsclient_config.Config

	PathMappings      []irodsfs_common_vpath.VPathMapping `json:"path_mappings,omitempty" yaml:"path_mappings,omitempty"`
	ReadAheadMax      int                                 `json:"read_ahead_max,omitempty" yaml:"read_ahead_max,omitempty"`
	NoPermissionCheck bool                                `json:"no_permission_check,omitempty" yaml:"no_permission_check,omitempty"`
	NoSetXattr        bool                                `json:"no_set_xattr,omitempty" yaml:"no_set_xattr,omitempty"`
	UID               int                                 `json:"uid,omitempty" yaml:"uid,omitempty"`
	GID               int                                 `json:"gid,omitempty" yaml:"gid,omitempty"`
	SystemUser        string                              `json:"system_user,omitempty" yaml:"system_user,omitempty"`
	MountPath         string                              `json:"mount_path,omitempty" yaml:"mount_path,omitempty"`

	MetadataConnection irodsclient_fs.ConnectionConfig `json:"metadata_connection,omitempty" yaml:"metadata_connection,omitempty"`
	IOConnection       irodsclient_fs.ConnectionConfig `json:"io_connection,omitempty" yaml:"io_connection,omitempty"`
	Cache              irodsclient_fs.CacheConfig      `json:"cache,omitempty" yaml:"cache,omitempty"`

	DataRootPath string `json:"data_root_path,omitempty" yaml:"data_root_path,omitempty"`
	LogPath      string `json:"log_path,omitempty" yaml:"log_path,omitempty"`

	PoolEndpoint string `json:"pool_endpoint,omitempty" yaml:"pool_endpoint,omitempty"`

	Profile            bool `json:"profile,omitempty" yaml:"profile,omitempty"`
	ProfileServicePort int  `json:"profile_service_port,omitempty" yaml:"profile_service_port,omitempty"`

	Foreground   bool   `json:"foreground,omitempty" yaml:"foreground,omitempty"`
	LogLevel     string `json:"log_level,omitempty" yaml:"log_level,omitempty"`
	Debug        bool   `json:"debug,omitempty" yaml:"debug,omitempty"`
	AllowOther   bool   `json:"allow_other,omitempty" yaml:"allow_other,omitempty"`
	Readonly     bool   `json:"readonly,omitempty" yaml:"readonly,omitempty"`
	ChildProcess bool   `json:"childprocess,omitempty" yaml:"childprocess,omitempty"`

	InstanceID  string   `json:"instanceid,omitempty" yaml:"instanceid,omitempty"`
	FuseOptions []string `json:"fuse_options,omitempty" yaml:"fuse_options,omitempty"`
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	systemUser, uid, gid, _ := utils.GetCurrentSystemUser()

	return &Config{
		Config:            *irodsclient_config.GetDefaultConfig(),
		PathMappings:      []irodsfs_common_vpath.VPathMapping{},
		ReadAheadMax:      ReadAheadMaxDefault,
		NoPermissionCheck: false,
		NoSetXattr:        false,
		UID:               uid,
		GID:               gid,
		SystemUser:        systemUser,
		MountPath:         "", // leave it empty

		MetadataConnection: irodsclient_fs.NewDefaultMetadataConnectionConfig(),
		IOConnection:       irodsclient_fs.NewDefaultIOConnectionConfig(),
		Cache:              irodsclient_fs.NewDefaultCacheConfig(),

		DataRootPath: GetDefaultDataRootDirPath(),
		LogPath:      "", // use default

		PoolEndpoint: "",

		Profile:            false,
		ProfileServicePort: ProfileServicePortDefault,

		Foreground:   false,
		LogLevel:     "",
		Debug:        false,
		AllowOther:   false,
		Readonly:     false,
		ChildProcess: false,

		InstanceID:  GetDefaultInstanceID(),
		FuseOptions: []string{},
	}
}

// NewConfigFromFile creates Config from file
func NewConfigFromFile(config *Config, filePath string) (*Config, error) {
	st, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, xerrors.Errorf("file %q does not exist: %w", filePath, err)
		}

		return nil, xerrors.Errorf("failed to stat file %q: %w", filePath, err)
	}

	if st.IsDir() {
		return NewConfigFromICommandsEnvDir(config, filePath)
	}

	ext := filepath.Ext(filePath)
	if ext == ".yaml" || ext == ".yml" {
		return NewConfigFromYAMLFile(config, filePath)
	}

	return NewConfigFromJSONFile(config, filePath)
}

// NewConfigFromYAMLFile creates Config from YAML
func NewConfigFromYAMLFile(config *Config, yamlPath string) (*Config, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}

	yamlBytes, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, xerrors.Errorf("failed to read YAML file %q: %w", yamlPath, err)
	}

	err = yaml.Unmarshal(yamlBytes, &cfg)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal YAML file %q to config: %w", yamlPath, err)
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
		return nil, xerrors.Errorf("failed to read YAML file %q: %w", jsonPath, err)
	}

	err = json.Unmarshal(jsonBytes, &cfg)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal JSON file %q to config: %w", jsonPath, err)
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

// NewConfigFromYAML creates Config from YAML
func NewConfigFromYAML(config *Config, yamlBytes []byte) (*Config, error) {
	cfg := Config{}
	if config != nil {
		cfg = *config
	}

	err := yaml.Unmarshal(yamlBytes, &cfg)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal YAML to config: %w", err)
	}

	// load icommands environment
	if len(cfg.AuthenticationFile) > 0 {
		if irodsclient_util.ExistFile(cfg.AuthenticationFile) {
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

// FixSystemSystemUserConfiguration fixes system user configuration
func (config *Config) FixSystemSystemUserConfiguration() error {
	systemUser, uid, gid, err := utils.CorrectSystemUser(config.SystemUser, config.UID, config.GID)
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
			config.PathMappings = []irodsfs_common_vpath.VPathMapping{
				{
					IRODSPath:           config.CurrentWorkingDir,
					MappingPath:         "/",
					ResourceType:        irodsfs_common_vpath.VPathMappingDirectory,
					ReadOnly:            false,
					CreateDir:           false,
					IgnoreNotExistError: false,
				},
			}
		} else if len(config.Home) > 0 {
			config.PathMappings = []irodsfs_common_vpath.VPathMapping{
				{
					IRODSPath:           config.Home,
					MappingPath:         "/",
					ResourceType:        irodsfs_common_vpath.VPathMappingDirectory,
					ReadOnly:            false,
					CreateDir:           false,
					IgnoreNotExistError: false,
				},
			}
		} else {
			iRODSHomePath := fmt.Sprintf("/%s/home/%s", config.ClientZoneName, config.ClientUsername)
			config.PathMappings = []irodsfs_common_vpath.VPathMapping{
				{
					IRODSPath:           iRODSHomePath,
					MappingPath:         "/",
					ResourceType:        irodsfs_common_vpath.VPathMappingDirectory,
					ReadOnly:            false,
					CreateDir:           false,
					IgnoreNotExistError: false,
				},
			}
		}
	}
}

// GetLogFilePath returns log file path
func (config *Config) GetLogFilePath() string {
	if len(config.LogPath) > 0 {
		return config.LogPath
	}

	// default
	logFilename := fmt.Sprintf("%s.log", config.InstanceID)
	return path.Join(config.DataRootPath, logFilename)
}

func (config *Config) GetInstanceDataRootDirPath() string {
	return path.Join(config.DataRootPath, config.InstanceID)
}

// MakeLogDir makes a log dir required
func (config *Config) MakeLogDir() error {
	logFilePath := config.GetLogFilePath()
	if logFilePath == "-" {
		// skip
		return nil
	}

	logDirPath := filepath.Dir(logFilePath)
	err := config.makeDir(logDirPath)
	if err != nil {
		return err
	}

	return nil
}

// makeDir makes a dir for use
func (config *Config) makeDir(path string) error {
	if len(path) == 0 {
		return xerrors.Errorf("failed to create a dir with empty path")
	}

	dirInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// make
			mkdirErr := os.MkdirAll(path, 0775)
			if mkdirErr != nil {
				return xerrors.Errorf("making a dir %q error: %w", path, mkdirErr)
			}

			return nil
		}

		return xerrors.Errorf("stating a dir %q error: %w", path, err)
	}

	if !dirInfo.IsDir() {
		return xerrors.Errorf("a file %q exist, not a directory", path)
	}

	dirPerm := dirInfo.Mode().Perm()
	if dirPerm&0200 != 0200 {
		return xerrors.Errorf("a dir %q exist, but does not have the write permission", path)
	}

	return nil
}

// Validate validates configuration
func (config *Config) Validate() error {
	if len(config.Host) == 0 {
		return xerrors.Errorf("hostname must be given")
	}

	if config.Port <= 0 {
		return xerrors.Errorf("port must be given")
	}

	if config.Profile && config.ProfileServicePort <= 0 {
		return xerrors.Errorf("profile service port must be given")
	}

	if len(config.Username) == 0 && len(config.ClientUsername) == 0 {
		return xerrors.Errorf("username or client username must be given")
	}

	if len(config.ZoneName) == 0 && len(config.ClientZoneName) == 0 {
		return xerrors.Errorf("zone name or client zone name must be given")
	}

	if len(config.PathMappings) == 0 {
		return xerrors.Errorf("path mappings must be given")
	}

	err := irodsfs_common_vpath.ValidateVPathMappings(config.PathMappings)
	if err != nil {
		return xerrors.Errorf("invalid path mappings: %w", err)
	}

	if config.UID < 0 {
		return xerrors.Errorf("invalid UID: %w", err)
	}

	if config.GID < 0 {
		return xerrors.Errorf("invalid GID: %w", err)
	}

	if len(config.MountPath) == 0 {
		return xerrors.Errorf("mount path must be given")
	}

	mountDirInfo, err := os.Stat(config.MountPath)
	if err != nil {
		return xerrors.Errorf("mountpoint %q error: %w", config.MountPath, err)
	}

	if !mountDirInfo.IsDir() {
		return xerrors.Errorf("mountpoint %q must be a directory", config.MountPath)
	}

	mountDirPerm := mountDirInfo.Mode().Perm()
	if mountDirPerm&0200 != 0200 {
		return xerrors.Errorf("mountpoint %q must have write permission", config.MountPath)
	}

	if len(config.DataRootPath) == 0 {
		return xerrors.Errorf("data root dir must be given")
	}

	if config.ReadAheadMax < 0 {
		return xerrors.Errorf("readahead max must be equal or greater than 0")
	}

	if config.MetadataConnection.MaxNumber < 1 {
		return xerrors.Errorf("metadata connection max must be equal or greater than 1")
	}

	if config.IOConnection.MaxNumber < 1 {
		return xerrors.Errorf("io connection max must be equal or greater than 1")
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
	access, err := ParseIRODSUrl(inputURL)
	if err != nil {
		return err
	}

	if len(access.Host) > 0 {
		config.Host = access.Host
	}

	if access.Port > 0 {
		config.Port = access.Port
	}

	if len(access.User) > 0 {
		config.Username = access.User
	}

	if len(access.Password) > 0 {
		config.Password = access.Password
	}

	if len(access.Zone) > 0 {
		config.ZoneName = access.Zone
	}

	if len(access.Path) > 0 {
		config.PathMappings = []irodsfs_common_vpath.VPathMapping{
			{
				IRODSPath:           access.Path,
				MappingPath:         "/",
				ResourceType:        irodsfs_common_vpath.VPathMappingDirectory,
				ReadOnly:            false,
				CreateDir:           false,
				IgnoreNotExistError: false,
			},
		}
	}

	return nil
}

// ParsePoolServiceEndpoint parses endpoint string
func ParsePoolServiceEndpoint(endpoint string) (string, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", xerrors.Errorf("could not parse endpoint: %v", err)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "tcp":
		return "tcp", u.Host, nil
	case "unix":
		path := path.Join("/", u.Path)
		return "unix", path, nil
	case "":
		if len(u.Host) > 0 {
			return "tcp", u.Host, nil
		}
		return "", "", xerrors.Errorf("unknown host: %q", u.Host)
	default:
		return "", "", xerrors.Errorf("unsupported protocol: %q", scheme)
	}
}
