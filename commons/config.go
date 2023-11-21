package commons

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	"golang.org/x/xerrors"

	"github.com/cyverse/irodsfs/utils"
	"github.com/rs/xid"
	yaml "gopkg.in/yaml.v2"
)

const (
	PortDefault                     int           = 1247
	ReadAheadMaxDefault             int           = 1024 * 128 // 128KB
	ConnectionMaxDefault            int           = 10
	TCPBufferSizeDefault            int           = 4 * 1024 * 1024 // 4MB
	ConnectionErrorTimeout          time.Duration = 1 * time.Minute
	OperationTimeoutDefault         time.Duration = 5 * time.Minute
	ConnectionLifespanDefault       time.Duration = 1 * time.Hour
	ConnectionIdleTimeoutDefault    time.Duration = 5 * time.Minute
	MetadataCacheTimeoutDefault     time.Duration = 5 * time.Minute
	MetadataCacheCleanupTimeDefault time.Duration = 5 * time.Minute

	AuthSchemeDefault          string = string(irodsclient_types.AuthSchemeNative)
	CSNegotiationDefault       string = string(irodsclient_types.CSNegotiationRequireTCP)
	EncryptionKeySizeDefault   int    = 32
	EncryptionAlgorithmDefault string = "AES-256-CBC"
	SaltSizeDefault            int    = 8
	HashRoundsDefault          int    = 16

	ProfileServicePortDefault int = 11021
)

func GetDefaultInstanceID() string {
	return xid.New().String()
}

func GetDefaultDataRootDirPath() string {
	dirPath, err := os.Getwd()
	if err != nil {
		return "/var/lib/irodsfs"
	}
	return dirPath
}

// MetadataCacheTimeoutSetting defines cache timeout for path
type MetadataCacheTimeoutSetting struct {
	Path    string                        `yaml:"path" json:"path"`
	Timeout irodsfs_common_utils.Duration `yaml:"timeout" json:"timeout"`
	Inherit bool                          `yaml:"inherit,omitempty" json:"inherit,omitempty"`
}

// Config holds the parameters list which can be configured
type Config struct {
	Host              string                              `yaml:"host"`
	Port              int                                 `yaml:"port"`
	ProxyUser         string                              `yaml:"proxy_user,omitempty"`
	ClientUser        string                              `yaml:"client_user"`
	Zone              string                              `yaml:"zone"`
	Password          string                              `yaml:"password,omitempty"`
	Resource          string                              `yaml:"resource,omitempty"`
	PathMappings      []irodsfs_common_vpath.VPathMapping `yaml:"path_mappings"`
	NoPermissionCheck bool                                `yaml:"no_permission_check"`
	UID               int                                 `yaml:"uid"`
	GID               int                                 `yaml:"gid"`
	SystemUser        string                              `yaml:"system_user"`
	MountPath         string                              `yaml:"mount_path,omitempty"`

	DataRootPath string `yaml:"data_root_path,omitempty"`

	LogPath string `yaml:"log_path,omitempty"`

	PoolEndpoint string `yaml:"pool_endpoint,omitempty"`

	AuthScheme              string `yaml:"auth_scheme"`
	ClientServerNegotiation bool   `yaml:"cs_negotiation"`
	CSNegotiationPolicy     string `yaml:"cs_negotiation_policy"`
	CACertificateFile       string `yaml:"ssl_ca_cert_file"`
	EncryptionKeySize       int    `yaml:"ssl_encryption_key_size"`
	EncryptionAlgorithm     string `yaml:"ssl_encryption_algorithm"`
	SaltSize                int    `yaml:"ssl_encryption_salt_size"`
	HashRounds              int    `yaml:"ssl_encryption_hash_rounds"`

	ReadAheadMax                          int                           `yaml:"read_ahead_max"`
	OperationTimeout                      irodsfs_common_utils.Duration `yaml:"operation_timeout"`
	ConnectionLifespan                    irodsfs_common_utils.Duration `yaml:"connection_lifespan"`
	ConnectionIdleTimeout                 irodsfs_common_utils.Duration `yaml:"connection_idle_timeout"`
	ConnectionMax                         int                           `yaml:"connection_max"`
	MetadataCacheTimeout                  irodsfs_common_utils.Duration `yaml:"metadata_cache_timeout"`
	MetadataCacheCleanupTime              irodsfs_common_utils.Duration `yaml:"metadata_cache_cleanup_time"`
	MetadataCacheTimeoutSettings          []MetadataCacheTimeoutSetting `yaml:"metadata_cache_timeout_settings"`
	StartNewTransaction                   bool                          `yaml:"start_new_transaction"`
	InvalidateParentEntryCacheImmediately bool                          `yaml:"invalidate_parent_entry_cache_immediately"`

	MonitorURL string `yaml:"monitor_url,omitempty"`

	Profile            bool `yaml:"profile,omitempty"`
	ProfileServicePort int  `yaml:"profile_service_port,omitempty"`

	Foreground   bool   `yaml:"foreground,omitempty"`
	LogLevel     string `yaml:"log_level,omitempty"`
	Debug        bool   `yaml:"debug,omitempty"`
	AllowOther   bool   `yaml:"allow_other,omitempty"`
	ChildProcess bool   `yaml:"childprocess,omitempty"`

	InstanceID  string   `yaml:"instanceid,omitempty"`
	FuseOptions []string `yaml:"fuse_options,omitempty"`
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	systemUser, uid, gid, _ := utils.GetCurrentSystemUser()

	return &Config{
		Host:              "",
		Port:              PortDefault,
		ProxyUser:         "",
		ClientUser:        "",
		Zone:              "",
		Password:          "",
		Resource:          "",
		PathMappings:      []irodsfs_common_vpath.VPathMapping{},
		NoPermissionCheck: false,
		UID:               uid,
		GID:               gid,
		SystemUser:        systemUser,

		DataRootPath: GetDefaultDataRootDirPath(),

		LogPath: "", // use default

		PoolEndpoint: "",

		AuthScheme:              AuthSchemeDefault,
		ClientServerNegotiation: false,
		CSNegotiationPolicy:     CSNegotiationDefault,
		CACertificateFile:       "",
		EncryptionKeySize:       EncryptionKeySizeDefault,
		EncryptionAlgorithm:     EncryptionAlgorithmDefault,
		SaltSize:                SaltSizeDefault,
		HashRounds:              HashRoundsDefault,

		ReadAheadMax:                          ReadAheadMaxDefault,
		OperationTimeout:                      irodsfs_common_utils.Duration(OperationTimeoutDefault),
		ConnectionLifespan:                    irodsfs_common_utils.Duration(ConnectionLifespanDefault),
		ConnectionIdleTimeout:                 irodsfs_common_utils.Duration(ConnectionIdleTimeoutDefault),
		ConnectionMax:                         ConnectionMaxDefault,
		MetadataCacheTimeout:                  irodsfs_common_utils.Duration(MetadataCacheTimeoutDefault),
		MetadataCacheCleanupTime:              irodsfs_common_utils.Duration(MetadataCacheCleanupTimeDefault),
		MetadataCacheTimeoutSettings:          []MetadataCacheTimeoutSetting{},
		StartNewTransaction:                   true,
		InvalidateParentEntryCacheImmediately: false,

		MonitorURL: "",

		Profile:            false,
		ProfileServicePort: ProfileServicePortDefault,

		Foreground:   false,
		LogLevel:     "",
		Debug:        false,
		AllowOther:   false,
		ChildProcess: false,

		InstanceID:  GetDefaultInstanceID(),
		FuseOptions: []string{},
	}
}

// NewConfigFromYAML creates Config from YAML
func NewConfigFromYAML(yamlBytes []byte) (*Config, error) {
	config := NewDefaultConfig()

	err := yaml.Unmarshal(yamlBytes, config)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal YAML: %w", err)
	}

	err = config.CorrectSystemUser()
	if err != nil {
		return nil, err
	}

	return config, nil
}

// NewConfigFromICommandsEnvironment creates Config from iCommands Environment dir path
func NewConfigFromICommandsEnvironment(configPath string) (*Config, error) {
	config, err := LoadICommandsEnvironmentFile(configPath)
	if err != nil {
		return nil, err
	}

	err = config.CorrectSystemUser()
	if err != nil {
		return nil, err
	}

	return config, nil
}

// CorrectSystemUser corrects system user configuration
func (config *Config) CorrectSystemUser() error {
	systemUser, uid, gid, err := utils.CorrectSystemUser(config.SystemUser, config.UID, config.GID)
	if err != nil {
		return err
	}

	config.SystemUser = systemUser
	config.UID = uid
	config.GID = gid
	return nil
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
				return xerrors.Errorf("making a dir (%s) error: %w", path, mkdirErr)
			}

			return nil
		}

		return xerrors.Errorf("stating a dir (%s) error: %w", path, err)
	}

	if !dirInfo.IsDir() {
		return xerrors.Errorf("a file (%s) exist, not a directory", path)
	}

	dirPerm := dirInfo.Mode().Perm()
	if dirPerm&0200 != 0200 {
		return xerrors.Errorf("a dir (%s) exist, but does not have the write permission", path)
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

	if len(config.ProxyUser) == 0 {
		return xerrors.Errorf("proxyUser must be given")
	}

	if len(config.ClientUser) == 0 {
		return xerrors.Errorf("clientUser must be given")
	}

	if len(config.Zone) == 0 {
		return xerrors.Errorf("zone must be given")
	}

	if len(config.Password) == 0 {
		return xerrors.Errorf("password must be given")
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
		return xerrors.Errorf("mountpoint (%s) error: %w", config.MountPath, err)
	}

	if !mountDirInfo.IsDir() {
		return xerrors.Errorf("mountpoint (%s) must be a directory", config.MountPath)
	}

	mountDirPerm := mountDirInfo.Mode().Perm()
	if mountDirPerm&0200 != 0200 {
		return xerrors.Errorf("mountpoint (%s) must have write permission", config.MountPath)
	}

	if len(config.DataRootPath) == 0 {
		return xerrors.Errorf("data root dir must be given")
	}

	if config.ReadAheadMax < 0 {
		return xerrors.Errorf("readahead max must be equal or greater than 0")
	}

	if config.ConnectionMax < 1 {
		return xerrors.Errorf("connection max must be equal or greater than 1")
	}

	authScheme, err := irodsclient_types.GetAuthScheme(config.AuthScheme)
	if err != nil {
		return err
	}

	if config.ClientServerNegotiation {
		if len(config.CSNegotiationPolicy) == 0 {
			return xerrors.Errorf("CS negotiation policy must be given")
		}
	}

	if authScheme == irodsclient_types.AuthSchemePAM {
		if _, err := os.Stat(config.CACertificateFile); os.IsNotExist(err) {
			return xerrors.Errorf("SSL CA Certificate file error: %w", err)
		}

		if config.EncryptionKeySize <= 0 {
			return xerrors.Errorf("SSL encryption key size must be given")
		}

		if len(config.EncryptionAlgorithm) == 0 {
			return xerrors.Errorf("SSL encryption algorithm must be given")
		}

		if config.SaltSize <= 0 {
			return xerrors.Errorf("SSL salt size must be given")
		}

		if config.HashRounds <= 0 {
			return xerrors.Errorf("SSL hash rounds must be given")
		}
	}

	if len(config.PoolEndpoint) > 0 {
		_, _, err := ParsePoolServiceEndpoint(config.PoolEndpoint)
		if err != nil {
			return err
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
		return "", "", xerrors.Errorf("unknown host: %s", u.Host)
	default:
		return "", "", xerrors.Errorf("unsupported protocol: %s", scheme)
	}
}

func IsYAMLFile(filePath string) bool {
	st, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	if st.IsDir() {
		return false
	}

	ext := filepath.Ext(filePath)
	return ext == ".yaml" || ext == ".yml"
}
