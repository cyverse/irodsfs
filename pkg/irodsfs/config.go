package irodsfs

import (
	"fmt"
	"os"
	"time"

	yaml "gopkg.in/yaml.v2"
)

const (
	PortDefault                     int           = 1247
	ReadAheadMaxDefault             int           = 1024 * 64 // 64KB
	ConnectionMaxDefault            int           = 10
	OperationTimeoutDefault         time.Duration = 5 * time.Minute
	ConnectionIdleTimeoutDefault    time.Duration = 5 * time.Minute
	MetadataCacheTimeoutDefault     time.Duration = 5 * time.Minute
	MetadataCacheCleanupTimeDefault time.Duration = 5 * time.Minute
	FileBufferStoragePathDefault    string        = "/tmp/irodsfs"
	FileBufferSizeMaxDefault        int64         = 1024 * 1024 * 1024 // 1GB
	AuthSchemePAM                   string        = "pam"
	AuthSchemeNative                string        = "native"
	AuthSchemeDefault               string        = AuthSchemeNative
	EncryptionKeySizeDefault        int           = 32
	EncryptionAlgorithmDefault      string        = "AES-256-CBC"
	SaltSizeDefault                 int           = 8
	HashRoundsDefault               int           = 16
)

// Config holds the parameters list which can be configured
type Config struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ProxyUser    string        `yaml:"proxy_user,omitempty"`
	ClientUser   string        `yaml:"client_user"`
	Zone         string        `yaml:"zone"`
	Password     string        `yaml:"password,omitempty"`
	PathMappings []PathMapping `yaml:"path_mappings"`
	UID          int           `yaml:"uid"`
	GID          int           `yaml:"gid"`
	MountPath    string        `yaml:"mount_path,omitempty"`

	AuthScheme          string `yaml:"authscheme"`
	CACertificateFile   string `yaml:"ssl_ca_cert_file"`
	EncryptionKeySize   int    `yaml:"ssl_encryption_key_size"`
	EncryptionAlgorithm string `yaml:"ssl_encryption_algorithm"`
	SaltSize            int    `yaml:"ssl_encryption_salt_size"`
	HashRounds          int    `yaml:"ssl_encryption_hash_rounds"`

	ReadAheadMax             int           `yaml:"read_ahead_max"`
	OperationTimeout         time.Duration `yaml:"operation_timeout"`
	ConnectionIdleTimeout    time.Duration `yaml:"connection_idle_timeout"`
	ConnectionMax            int           `yaml:"connection_max"`
	MetadataCacheTimeout     time.Duration `yaml:"metadata_cache_timeout"`
	MetadataCacheCleanupTime time.Duration `yaml:"metadata_cache_cleanup_time"`
	FileBufferStoragePath    string        `yaml:"file_buffer_storage_path"`
	FileBufferSizeMax        int64         `yaml:"file_buffer_size_max"`

	LogPath    string `yaml:"log_path,omitempty"`
	MonitorURL string `yaml:"monitor_url,omitempty"`

	Foreground   bool `yaml:"foreground,omitempty"`
	AllowOther   bool `yaml:"allow_other,omitempty"`
	ChildProcess bool `yaml:"childprocess,omitempty"`
}

type configAlias struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ProxyUser    string        `yaml:"proxy_user,omitempty"`
	ClientUser   string        `yaml:"client_user"`
	Zone         string        `yaml:"zone"`
	Password     string        `yaml:"password,omitempty"`
	PathMappings []PathMapping `yaml:"path_mappings"`
	UID          int           `yaml:"uid"`
	GID          int           `yaml:"gid"`
	MountPath    string        `yaml:"mount_path,omitempty"`

	AuthScheme          string `yaml:"authscheme"`
	CACertificateFile   string `yaml:"ssl_ca_cert_file"`
	EncryptionKeySize   int    `yaml:"ssl_encryption_key_size"`
	EncryptionAlgorithm string `yaml:"ssl_encryption_algorithm"`
	SaltSize            int    `yaml:"ssl_encryption_salt_size"`
	HashRounds          int    `yaml:"ssl_encryption_hash_rounds"`

	ReadAheadMax             int    `yaml:"read_ahead_max"`
	OperationTimeout         string `yaml:"operation_timeout"`
	ConnectionIdleTimeout    string `yaml:"connection_idle_timeout"`
	ConnectionMax            int    `yaml:"connection_max"`
	MetadataCacheTimeout     string `yaml:"metadata_cache_timeout"`
	MetadataCacheCleanupTime string `yaml:"metadata_cache_cleanup_time"`
	FileBufferStoragePath    string `yaml:"file_buffer_storage_path"`
	FileBufferSizeMax        int64  `yaml:"file_buffer_size_max"`

	LogPath    string `yaml:"log_path,omitempty"`
	MonitorURL string `yaml:"monitor_url,omitempty"`

	Foreground   bool `yaml:"foreground,omitempty"`
	AllowOther   bool `yaml:"allow_other,omitempty"`
	ChildProcess bool `yaml:"childprocess,omitempty"`
}

// NewDefaultConfig creates DefaultConfig
func NewDefaultConfig() *Config {
	return &Config{
		Port:         PortDefault,
		PathMappings: []PathMapping{},
		UID:          -1,
		GID:          -1,

		AuthScheme:          AuthSchemeDefault,
		EncryptionKeySize:   EncryptionKeySizeDefault,
		EncryptionAlgorithm: EncryptionAlgorithmDefault,
		SaltSize:            SaltSizeDefault,
		HashRounds:          HashRoundsDefault,

		ReadAheadMax:             ReadAheadMaxDefault,
		OperationTimeout:         OperationTimeoutDefault,
		ConnectionIdleTimeout:    ConnectionIdleTimeoutDefault,
		ConnectionMax:            ConnectionMaxDefault,
		MetadataCacheTimeout:     MetadataCacheTimeoutDefault,
		MetadataCacheCleanupTime: MetadataCacheCleanupTimeDefault,
		FileBufferStoragePath:    FileBufferStoragePathDefault,
		FileBufferSizeMax:        FileBufferSizeMaxDefault,

		LogPath:    "",
		MonitorURL: "",

		Foreground:   false,
		AllowOther:   false,
		ChildProcess: false,
	}
}

// NewConfigFromYAML creates Config from YAML
func NewConfigFromYAML(yamlBytes []byte) (*Config, error) {
	alias := configAlias{
		Port:         PortDefault,
		PathMappings: []PathMapping{},
		UID:          -1,
		GID:          -1,

		AuthScheme:          AuthSchemeDefault,
		EncryptionKeySize:   EncryptionKeySizeDefault,
		EncryptionAlgorithm: EncryptionAlgorithmDefault,
		SaltSize:            SaltSizeDefault,
		HashRounds:          HashRoundsDefault,

		ReadAheadMax:          ReadAheadMaxDefault,
		ConnectionMax:         ConnectionMaxDefault,
		FileBufferStoragePath: FileBufferStoragePathDefault,
		FileBufferSizeMax:     FileBufferSizeMaxDefault,

		LogPath:    "",
		MonitorURL: "",

		Foreground:   false,
		AllowOther:   false,
		ChildProcess: false,
	}

	err := yaml.Unmarshal(yamlBytes, &alias)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML - %v", err)
	}

	var operationTimeout time.Duration
	if len(alias.OperationTimeout) > 0 {
		operationTimeout, err = time.ParseDuration(alias.OperationTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML - %v", err)
		}
	} else {
		operationTimeout = OperationTimeoutDefault
	}

	var connectionIdleTimeout time.Duration
	if len(alias.ConnectionIdleTimeout) > 0 {
		connectionIdleTimeout, err = time.ParseDuration(alias.ConnectionIdleTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML - %v", err)
		}
	} else {
		connectionIdleTimeout = ConnectionIdleTimeoutDefault
	}

	var metadataCacheTimeout time.Duration
	if len(alias.MetadataCacheTimeout) > 0 {
		metadataCacheTimeout, err = time.ParseDuration(alias.MetadataCacheTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML - %v", err)
		}
	} else {
		metadataCacheTimeout = MetadataCacheTimeoutDefault
	}

	var metadataCacheCleanupTime time.Duration
	if len(alias.MetadataCacheCleanupTime) > 0 {
		metadataCacheCleanupTime, err = time.ParseDuration(alias.MetadataCacheCleanupTime)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML - %v", err)
		}
	} else {
		metadataCacheCleanupTime = MetadataCacheCleanupTimeDefault
	}

	return &Config{
		Host:         alias.Host,
		Port:         alias.Port,
		ProxyUser:    alias.ProxyUser,
		ClientUser:   alias.ClientUser,
		Zone:         alias.Zone,
		Password:     alias.Password,
		PathMappings: alias.PathMappings,
		UID:          alias.UID,
		GID:          alias.GID,
		MountPath:    alias.MountPath,

		AuthScheme:          alias.AuthScheme,
		CACertificateFile:   alias.CACertificateFile,
		EncryptionKeySize:   alias.EncryptionKeySize,
		EncryptionAlgorithm: alias.EncryptionAlgorithm,
		SaltSize:            alias.SaltSize,
		HashRounds:          alias.HashRounds,

		ReadAheadMax:             alias.ReadAheadMax,
		OperationTimeout:         operationTimeout,
		ConnectionIdleTimeout:    connectionIdleTimeout,
		ConnectionMax:            alias.ConnectionMax,
		MetadataCacheTimeout:     metadataCacheTimeout,
		MetadataCacheCleanupTime: metadataCacheCleanupTime,
		FileBufferStoragePath:    alias.FileBufferStoragePath,
		FileBufferSizeMax:        alias.FileBufferSizeMax,

		LogPath:    alias.LogPath,
		MonitorURL: alias.MonitorURL,

		Foreground:   alias.Foreground,
		AllowOther:   alias.AllowOther,
		ChildProcess: alias.ChildProcess,
	}, nil
}

// Validate validates configuration
func (config *Config) Validate() error {
	if len(config.Host) == 0 {
		return fmt.Errorf("hostname must be given")
	}

	if config.Port <= 0 {
		return fmt.Errorf("port must be given")
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

	err := ValidatePathMappings(config.PathMappings)
	if err != nil {
		return fmt.Errorf("invalid path mappings - %v", err)
	}

	if len(config.MountPath) == 0 {
		return fmt.Errorf("mount path must be given")
	}

	fileinfo, err := os.Stat(config.MountPath)
	if err != nil {
		return fmt.Errorf("mountpoint (%s) error - %v", config.MountPath, err)
	}

	if !fileinfo.IsDir() {
		return fmt.Errorf("mountpoint (%s) must be a directory", config.MountPath)
	}

	if config.ReadAheadMax < 0 {
		return fmt.Errorf("readahead max must be equal or greater than 0")
	}

	if config.ConnectionMax < 1 {
		return fmt.Errorf("connection max must be equal or greater than 1")
	}

	if len(config.FileBufferStoragePath) == 0 {
		return fmt.Errorf("file buffer storage path must be given")
	}

	if config.FileBufferSizeMax < 10485760 {
		return fmt.Errorf("file buffer size max must be equal or greater than 10485760")
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
