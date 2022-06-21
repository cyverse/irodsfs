package commons

import (
	"fmt"
	"os"
	"time"

	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"

	"github.com/cyverse/irodsfs/utils"
	"github.com/rs/xid"
	yaml "gopkg.in/yaml.v2"
)

const (
	PortDefault                     int           = 1247
	ReadAheadMaxDefault             int           = 1024 * 64 // 64KB
	ConnectionMaxDefault            int           = 10
	OperationTimeoutDefault         time.Duration = 5 * time.Minute
	ConnectionLifespanDefault       time.Duration = 1 * time.Hour
	ConnectionIdleTimeoutDefault    time.Duration = 5 * time.Minute
	MetadataCacheTimeoutDefault     time.Duration = 5 * time.Minute
	MetadataCacheCleanupTimeDefault time.Duration = 5 * time.Minute

	LogFilePathPrefixDefault   string = "/tmp/irodsfs"
	LogFilePathChildDefault    string = "/tmp/irodsfs_child.log"
	TempRootPathPrefixDefault  string = "/tmp/irodsfs_temp"
	AuthSchemePAM              string = "pam"
	AuthSchemeNative           string = "native"
	AuthSchemeDefault          string = AuthSchemeNative
	EncryptionKeySizeDefault   int    = 32
	EncryptionAlgorithmDefault string = "AES-256-CBC"
	SaltSizeDefault            int    = 8
	HashRoundsDefault          int    = 16
	ProfileServicePortDefault  int    = 11021
)

var (
	instanceID string
)

// getInstanceID returns instance ID
func getInstanceID() string {
	if len(instanceID) == 0 {
		instanceID = xid.New().String()
	}

	return instanceID
}

// GetDefaultLogFilePath returns default log file path
func GetDefaultLogFilePath() string {
	return fmt.Sprintf("%s_%s.log", LogFilePathPrefixDefault, getInstanceID())
}

// GetDefaultTempRootPath returns default temp root path
func GetDefaultTempRootPath() string {
	return fmt.Sprintf("%s_%s", TempRootPathPrefixDefault, getInstanceID())
}

// MetadataCacheTimeoutSetting defines cache timeout for path
type MetadataCacheTimeoutSetting struct {
	Path    string                        `yaml:"path" json:"path"`
	Timeout irodsfs_common_utils.Duration `yaml:"timeout" json:"timeout"`
	Inherit bool                          `yaml:"inherit,omitempty" json:"inherit,omitempty"`
}

// Config holds the parameters list which can be configured
type Config struct {
	Host         string                              `yaml:"host"`
	Port         int                                 `yaml:"port"`
	ProxyUser    string                              `yaml:"proxy_user,omitempty"`
	ClientUser   string                              `yaml:"client_user"`
	Zone         string                              `yaml:"zone"`
	Password     string                              `yaml:"password,omitempty"`
	Resource     string                              `yaml:"resource,omitempty"`
	PathMappings []irodsfs_common_vpath.VPathMapping `yaml:"path_mappings"`
	UID          int                                 `yaml:"uid"`
	GID          int                                 `yaml:"gid"`
	SystemUser   string                              `yaml:"system_user"`
	MountPath    string                              `yaml:"mount_path,omitempty"`

	TempRootPath string `yaml:"temp_root_path,omitempty"`

	PoolHost string `yaml:"pool_host,omitempty"`
	PoolPort int    `yaml:"pool_port,omitempty"`

	AuthScheme          string `yaml:"authscheme"`
	CACertificateFile   string `yaml:"ssl_ca_cert_file"`
	EncryptionKeySize   int    `yaml:"ssl_encryption_key_size"`
	EncryptionAlgorithm string `yaml:"ssl_encryption_algorithm"`
	SaltSize            int    `yaml:"ssl_encryption_salt_size"`
	HashRounds          int    `yaml:"ssl_encryption_hash_rounds"`

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

	LogPath    string `yaml:"log_path,omitempty"`
	MonitorURL string `yaml:"monitor_url,omitempty"`

	Profile            bool `yaml:"profile,omitempty"`
	ProfileServicePort int  `yaml:"profile_service_port,omitempty"`

	Foreground   bool `yaml:"foreground,omitempty"`
	Debug        bool `yaml:"debug,omitempty"`
	AllowOther   bool `yaml:"allow_other,omitempty"`
	ChildProcess bool `yaml:"childprocess,omitempty"`

	InstanceID string `yaml:"instanceid,omitempty"`
}

// NewDefaultConfig creates DefaultConfig
func NewDefaultConfig() *Config {
	systemUser, uid, gid, _ := utils.GetCurrentSystemUser()

	return &Config{
		Port:         PortDefault,
		Resource:     "",
		PathMappings: []irodsfs_common_vpath.VPathMapping{},
		UID:          uid,
		GID:          gid,
		SystemUser:   systemUser,

		PoolHost: "",
		PoolPort: 0,

		TempRootPath: GetDefaultTempRootPath(),

		AuthScheme:          AuthSchemeDefault,
		EncryptionKeySize:   EncryptionKeySizeDefault,
		EncryptionAlgorithm: EncryptionAlgorithmDefault,
		SaltSize:            SaltSizeDefault,
		HashRounds:          HashRoundsDefault,

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

		LogPath:    GetDefaultLogFilePath(),
		MonitorURL: "",

		Profile:            false,
		ProfileServicePort: ProfileServicePortDefault,

		Foreground:   false,
		Debug:        false,
		AllowOther:   false,
		ChildProcess: false,

		InstanceID: getInstanceID(),
	}
}

// NewConfigFromYAML creates Config from YAML
func NewConfigFromYAML(yamlBytes []byte) (*Config, error) {
	systemUser, uid, gid, _ := utils.GetCurrentSystemUser()

	config := Config{
		Port:         PortDefault,
		Resource:     "",
		PathMappings: []irodsfs_common_vpath.VPathMapping{},
		UID:          uid,
		GID:          gid,
		SystemUser:   systemUser,

		PoolHost: "",
		PoolPort: 0,

		TempRootPath: GetDefaultTempRootPath(),

		AuthScheme:          AuthSchemeDefault,
		EncryptionKeySize:   EncryptionKeySizeDefault,
		EncryptionAlgorithm: EncryptionAlgorithmDefault,
		SaltSize:            SaltSizeDefault,
		HashRounds:          HashRoundsDefault,

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

		LogPath:    GetDefaultLogFilePath(),
		MonitorURL: "",

		Profile:            false,
		ProfileServicePort: ProfileServicePortDefault,

		Foreground:   false,
		Debug:        false,
		AllowOther:   false,
		ChildProcess: false,

		InstanceID: getInstanceID(),
	}

	err := yaml.Unmarshal(yamlBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML - %v", err)
	}

	err = config.CorrectSystemUser()
	if err != nil {
		return nil, fmt.Errorf("failed to correct System User - %v", err)
	}

	return &config, nil
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

// MakeTempRootDir makes temp root dir
func (config *Config) MakeTempRootDir() error {
	if len(config.TempRootPath) == 0 {
		return nil
	}

	tempDirInfo, err := os.Stat(config.TempRootPath)
	if err != nil {
		if os.IsNotExist(err) {
			// make
			mkdirErr := os.MkdirAll(config.TempRootPath, 0775)
			if mkdirErr != nil {
				return fmt.Errorf("making a temp root dir (%s) error - %v", config.TempRootPath, mkdirErr)
			}

			return nil
		}

		return fmt.Errorf("temp root dir (%s) error - %v", config.TempRootPath, err)
	}

	if !tempDirInfo.IsDir() {
		return fmt.Errorf("temp root dir (%s) exist, but not a directory", config.TempRootPath)
	}

	tempDirPerm := tempDirInfo.Mode().Perm()
	if tempDirPerm&0200 != 0200 {
		return fmt.Errorf("temp root dir (%s) exist, but does not have write permission", config.TempRootPath)
	}

	return nil
}

// RemoveTempRootDir removes temp root dir
func (config *Config) RemoveTempRootDir() error {
	if len(config.TempRootPath) == 0 {
		return nil
	}

	return os.RemoveAll(config.TempRootPath)
}

// Validate validates configuration
func (config *Config) Validate() error {
	if len(config.Host) == 0 {
		return fmt.Errorf("hostname must be given")
	}

	if config.Port <= 0 {
		return fmt.Errorf("port must be given")
	}

	if config.Profile && config.ProfileServicePort <= 0 {
		return fmt.Errorf("profile service port must be given")
	}

	if len(config.ProxyUser) == 0 {
		return fmt.Errorf("proxyUser must be given")
	}

	if len(config.ClientUser) == 0 {
		return fmt.Errorf("clientUser must be given")
	}

	if len(config.Zone) == 0 {
		return fmt.Errorf("zone must be given")
	}

	if len(config.Password) == 0 {
		return fmt.Errorf("password must be given")
	}

	if len(config.PathMappings) == 0 {
		return fmt.Errorf("path mappings must be given")
	}

	err := irodsfs_common_vpath.ValidateVPathMappings(config.PathMappings)
	if err != nil {
		return fmt.Errorf("invalid path mappings - %v", err)
	}

	if config.UID < 0 {
		return fmt.Errorf("invalid UID - %v", err)
	}

	if config.GID < 0 {
		return fmt.Errorf("invalid GID - %v", err)
	}

	if len(config.MountPath) == 0 {
		return fmt.Errorf("mount path must be given")
	}

	mountDirInfo, err := os.Stat(config.MountPath)
	if err != nil {
		return fmt.Errorf("mountpoint (%s) error - %v", config.MountPath, err)
	}

	if !mountDirInfo.IsDir() {
		return fmt.Errorf("mountpoint (%s) must be a directory", config.MountPath)
	}

	mountDirPerm := mountDirInfo.Mode().Perm()
	if mountDirPerm&0200 != 0200 {
		return fmt.Errorf("mountpoint (%s) must have write permission", config.MountPath)
	}

	if len(config.TempRootPath) > 0 {
		tempDirInfo, err := os.Stat(config.TempRootPath)
		if err != nil {
			return fmt.Errorf("temp root dir (%s) error - %v", config.TempRootPath, err)
		}

		if !tempDirInfo.IsDir() {
			return fmt.Errorf("temp root dir (%s) must be a directory", config.TempRootPath)
		}

		tempDirPerm := tempDirInfo.Mode().Perm()
		if tempDirPerm&0200 != 0200 {
			return fmt.Errorf("temp root (%s) must have write permission", config.TempRootPath)
		}
	}

	if config.ReadAheadMax < 0 {
		return fmt.Errorf("readahead max must be equal or greater than 0")
	}

	if config.ConnectionMax < 1 {
		return fmt.Errorf("connection max must be equal or greater than 1")
	}

	if config.AuthScheme != AuthSchemePAM && config.AuthScheme != AuthSchemeNative {
		return fmt.Errorf("unknown auth scheme - %v", config.AuthScheme)
	}

	if config.AuthScheme == AuthSchemePAM {
		if _, err := os.Stat(config.CACertificateFile); os.IsNotExist(err) {
			return fmt.Errorf("SSL CA Certificate file error - %v", err)
		}

		if config.EncryptionKeySize <= 0 {
			return fmt.Errorf("SSL encryption key size must be given")
		}

		if len(config.EncryptionAlgorithm) == 0 {
			return fmt.Errorf("SSL encryption algorithm must be given")
		}

		if config.SaltSize <= 0 {
			return fmt.Errorf("SSL salt size must be given")
		}

		if config.HashRounds <= 0 {
			return fmt.Errorf("SSL hash rounds must be given")
		}
	}

	return nil
}
