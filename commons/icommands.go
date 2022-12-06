package commons

import (
	"fmt"
	"os"
	"path/filepath"

	irodsclient_icommands "github.com/cyverse/go-irodsclient/utils/icommands"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	log "github.com/sirupsen/logrus"
)

func isICommandsEnvDir(dirPath string) bool {
	st, err := os.Stat(dirPath)
	if err != nil {
		return false
	}

	if !st.IsDir() {
		return false
	}

	envFilePath := filepath.Join(dirPath, "irods_environment.json")
	passFilePath := filepath.Join(dirPath, ".irodsA")

	stEnv, err := os.Stat(envFilePath)
	if err != nil {
		return false
	}

	if stEnv.IsDir() {
		return false
	}

	stPass, err := os.Stat(passFilePath)
	if err != nil {
		return false
	}

	if stPass.IsDir() {
		return false
	}

	return true
}

func LoadICommandsEnvironmentDir(configDirPath string) (*Config, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "LoadICommandsEnvironmentDir",
	})

	configDirPath, err := filepath.Abs(configDirPath)
	if err != nil {
		return nil, err
	}

	// check if it is iRODS FUSE Lite Config YAML or iCommands JSON file
	if isICommandsEnvDir(configDirPath) {
		logger.Debugf("reading iCommands environment dir - %s", configDirPath)

		envFilePath := filepath.Join(configDirPath, "irods_environment.json")
		return LoadICommandsEnvironmentFile(envFilePath)
	}

	return nil, fmt.Errorf("failed to read iCommands environment dir %s", configDirPath)
}

func LoadICommandsEnvironmentFile(configPath string) (*Config, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "LoadICommandsEnvironmentFile",
	})

	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}

	logger.Debugf("reading iCommands environment file - %s", configPath)

	// read from iCommands JSON File
	iCommandsEnvMgr, err := irodsclient_icommands.CreateIcommandsEnvironmentManager()
	if err != nil {
		return nil, err
	}

	iCommandsEnvMgr.SetEnvironmentFilePath(configPath)

	err = iCommandsEnvMgr.Load(os.Getppid())
	if err != nil {
		return nil, err
	}

	loadedAccount, err := iCommandsEnvMgr.ToIRODSAccount()
	if err != nil {
		return nil, err
	}

	config := NewDefaultConfig()

	// Fill more
	config.AuthScheme = string(loadedAccount.AuthenticationScheme)
	config.CSNegotiationPolicy = string(loadedAccount.CSNegotiationPolicy)
	config.ClientServerNegotiation = loadedAccount.ClientServerNegotiation
	config.Host = loadedAccount.Host
	config.Port = loadedAccount.Port
	config.ClientUser = loadedAccount.ClientUser
	config.Zone = loadedAccount.ClientZone
	config.ProxyUser = loadedAccount.ProxyUser
	config.Password = loadedAccount.Password
	config.Resource = loadedAccount.DefaultResource
	config.CACertificateFile = loadedAccount.SSLConfiguration.CACertificateFile
	config.EncryptionKeySize = loadedAccount.SSLConfiguration.EncryptionKeySize
	config.EncryptionAlgorithm = loadedAccount.SSLConfiguration.EncryptionAlgorithm
	config.SaltSize = loadedAccount.SSLConfiguration.SaltSize
	config.HashRounds = loadedAccount.SSLConfiguration.HashRounds
	if iCommandsEnvMgr.Session != nil {
		if len(iCommandsEnvMgr.Session.CurrentWorkingDir) > 0 {
			config.PathMappings = []irodsfs_common_vpath.VPathMapping{
				{
					IRODSPath:           iCommandsEnvMgr.Session.CurrentWorkingDir,
					MappingPath:         "/",
					ResourceType:        irodsfs_common_vpath.VPathMappingDirectory,
					ReadOnly:            false,
					CreateDir:           false,
					IgnoreNotExistError: false,
				},
			}
		}
	}

	if len(config.PathMappings) == 0 {
		iRODSHomePath := fmt.Sprintf("/%s/home/%s", config.Zone, config.ClientUser)
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

	return config, nil
}
