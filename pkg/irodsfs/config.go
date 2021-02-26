package irodsfs

import (
	"fmt"
	"os"
	"time"

	yaml "gopkg.in/yaml.v2"
)

const (
	BlockSizeDefault             int           = 1024 * 64     // 64KB
	ReadAheadMaxDefault          int           = 1024 * 64 * 4 // 4*64KB
	UseBlockIODefault            bool          = true
	PerFileBlockCacheMaxDefault  int           = 3
	ConnectionMaxDefault         int           = 10
	OperationTimeoutDefault      time.Duration = 5 * time.Minute
	ConnectionIdleTimeoutDefault time.Duration = 5 * time.Minute
	CacheTimeoutDefault          time.Duration = 5 * time.Minute
	CacheCleanupTimeDefault      time.Duration = 5 * time.Minute
)

// Config holds the parameters list which can be configured
type Config struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	ProxyUser  string `yaml:"proxy_user,omitempty"`
	ClientUser string `yaml:"client_user"`
	Zone       string `yaml:"zone"`
	Password   string `yaml:"password,omitempty"`
	IRODSPath  string `yaml:"irods_path,omitempty"` // e.g., /ZONE/home/iychoi
	MountPath  string `yaml:"mount_path,omitempty"`

	BlockSize             int           `yaml:"block_size"`
	ReadAheadMax          int           `yaml:"read_ahead_max"`
	UseBlockIO            bool          `yaml:"use_block_io"`
	PerFileBlockCacheMax  int           `yaml:"per_file_block_cache_max"`
	OperationTimeout      time.Duration `yaml:"operation_timeout"`
	ConnectionIdleTimeout time.Duration `yaml:"connection_idle_timeout"`
	ConnectionMax         int           `yaml:"connection_max"`
	CacheTimeout          time.Duration `yaml:"cache_timeout"`
	CacheCleanupTime      time.Duration `yaml:"cache_cleanup_time"`

	Foreground   bool `yaml:"foreground,omitempty"`
	ChildProcess bool `yaml:"childprocess,omitempty"`
}

type configAlias struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	ProxyUser  string `yaml:"proxy_user,omitempty"`
	ClientUser string `yaml:"client_user"`
	Zone       string `yaml:"zone"`
	Password   string `yaml:"password,omitempty"`
	IRODSPath  string `yaml:"irods_path,omitempty"`
	MountPath  string `yaml:"mount_path,omitempty"`

	BlockSize             int    `yaml:"block_size"`
	ReadAheadMax          int    `yaml:"read_ahead_max"`
	UseBlockIO            bool   `yaml:"use_block_io"`
	PerFileBlockCacheMax  int    `yaml:"per_file_block_cache_max"`
	OperationTimeout      string `yaml:"operation_timeout"`
	ConnectionIdleTimeout string `yaml:"connection_idle_timeout"`
	ConnectionMax         int    `yaml:"connection_max"`
	CacheTimeout          string `yaml:"cache_timeout"`
	CacheCleanupTime      string `yaml:"cache_cleanup_time"`

	Foreground   bool `yaml:"foreground,omitempty"`
	ChildProcess bool `yaml:"childprocess,omitempty"`
}

// NewDefaultConfig creates DefaultConfig
func NewDefaultConfig() *Config {
	return &Config{
		Port: 0,

		BlockSize:             BlockSizeDefault,
		ReadAheadMax:          ReadAheadMaxDefault,
		UseBlockIO:            UseBlockIODefault,
		PerFileBlockCacheMax:  PerFileBlockCacheMaxDefault,
		OperationTimeout:      OperationTimeoutDefault,
		ConnectionIdleTimeout: ConnectionIdleTimeoutDefault,
		ConnectionMax:         ConnectionMaxDefault,
		CacheTimeout:          CacheTimeoutDefault,
		CacheCleanupTime:      CacheCleanupTimeDefault,

		Foreground: false,
	}
}

// NewConfigFromYAML creates Config from YAML
func NewConfigFromYAML(yamlBytes []byte) (*Config, error) {
	alias := configAlias{
		BlockSize:            BlockSizeDefault,
		ReadAheadMax:         ReadAheadMaxDefault,
		PerFileBlockCacheMax: PerFileBlockCacheMaxDefault,
		UseBlockIO:           UseBlockIODefault,
		ConnectionMax:        ConnectionMaxDefault,
	}

	err := yaml.Unmarshal(yamlBytes, &alias)
	if err != nil {
		return nil, fmt.Errorf("YAML Unmarshal Error - %v", err)
	}

	var operationTimeout time.Duration
	if len(alias.OperationTimeout) > 0 {
		operationTimeout, err = time.ParseDuration(alias.OperationTimeout)
		if err != nil {
			return nil, fmt.Errorf("YAML Unmarshal Error - %v", err)
		}
	} else {
		operationTimeout = OperationTimeoutDefault
	}

	var connectionIdleTimeout time.Duration
	if len(alias.ConnectionIdleTimeout) > 0 {
		connectionIdleTimeout, err = time.ParseDuration(alias.ConnectionIdleTimeout)
		if err != nil {
			return nil, fmt.Errorf("YAML Unmarshal Error - %v", err)
		}
	} else {
		connectionIdleTimeout = ConnectionIdleTimeoutDefault
	}

	var cacheTimeout time.Duration
	if len(alias.CacheTimeout) > 0 {
		cacheTimeout, err = time.ParseDuration(alias.CacheTimeout)
		if err != nil {
			return nil, fmt.Errorf("YAML Unmarshal Error - %v", err)
		}
	} else {
		cacheTimeout = CacheTimeoutDefault
	}

	var cacheCleanupTime time.Duration
	if len(alias.CacheCleanupTime) > 0 {
		cacheCleanupTime, err = time.ParseDuration(alias.CacheCleanupTime)
		if err != nil {
			return nil, fmt.Errorf("YAML Unmarshal Error - %v", err)
		}
	} else {
		cacheCleanupTime = CacheCleanupTimeDefault
	}

	return &Config{
		Host:       alias.Host,
		Port:       alias.Port,
		ProxyUser:  alias.ProxyUser,
		ClientUser: alias.ClientUser,
		Zone:       alias.Zone,
		Password:   alias.Password,
		IRODSPath:  alias.IRODSPath,
		MountPath:  alias.MountPath,

		BlockSize:             alias.BlockSize,
		ReadAheadMax:          alias.ReadAheadMax,
		UseBlockIO:            alias.UseBlockIO,
		PerFileBlockCacheMax:  alias.PerFileBlockCacheMax,
		OperationTimeout:      operationTimeout,
		ConnectionIdleTimeout: connectionIdleTimeout,
		ConnectionMax:         alias.ConnectionMax,
		CacheTimeout:          cacheTimeout,
		CacheCleanupTime:      cacheCleanupTime,

		Foreground: alias.Foreground,
	}, nil
}

// Validate validates configuration
func (config *Config) Validate() error {
	if len(config.Host) == 0 {
		return fmt.Errorf("Hostname must be given")
	}

	if config.Port <= 0 {
		return fmt.Errorf("Port must be given")
	}

	if len(config.ProxyUser) == 0 {
		return fmt.Errorf("ProxyUser must be given")
	}

	if len(config.ClientUser) == 0 {
		return fmt.Errorf("ClientUser must be given")
	}

	if len(config.Zone) == 0 {
		return fmt.Errorf("Zone must be given")
	}

	if len(config.Password) == 0 {
		return fmt.Errorf("Password must be given")
	}

	if len(config.IRODSPath) == 0 {
		return fmt.Errorf("IRODSPath must be given")
	}

	if len(config.MountPath) == 0 {
		return fmt.Errorf("MountPath must be given")
	}

	fileinfo, err := os.Stat(config.MountPath)
	if err != nil {
		return fmt.Errorf("mountpoint (%s) error - %v", config.MountPath, err)
	}

	if !fileinfo.IsDir() {
		return fmt.Errorf("mountpoint (%s) must be a directory", config.MountPath)
	}

	if config.BlockSize < 1024 {
		return fmt.Errorf("BlockSize must be greater than 1024 Bytes")
	}

	if config.ReadAheadMax < 0 {
		return fmt.Errorf("ReadAheadMax must be equal or greater than 0")
	}

	if config.PerFileBlockCacheMax < 0 {
		return fmt.Errorf("PerFileBlockCacheMax must be greater than 0")
	}

	if config.ConnectionMax < 1 {
		return fmt.Errorf("ConnectionMax must be equal or greater than 1")
	}

	return nil
}
