package server

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/pkg/errors"
)

const (
	testServerHost          string = "localhost"
	testServerPort          int    = 1247
	testServerAdminUser     string = "rods"
	testServerAdminPassword string = "rods"
	testServerZone          string = "tempZone"
	testServerResource      string = "demoResc"

	productionServerHost          string = "data.cyverse.org"
	productionServerPort          int    = 1247
	productionServerAdminUser     string = ""
	productionServerAdminPassword string = ""
	productionServerZone          string = "iplant"
	productionServerResource      string = ""
)

type IRODSServerInfo struct {
	Name                string
	Version             string
	AuthScheme          types.AuthScheme
	CSNegotiation       bool
	CSNegotiationPolicy types.CSNegotiationPolicyRequest

	ComposeFile        string
	UseAddressResolver bool

	Host     string
	Port     int
	User     string
	Password string
	Zone     string
	Resource string

	// Cache backend configuration
	CacheBackendType fs.CacheBackendType // "memory", "ristretto", "redis", "none"
	RedisAddress     string              // for redis backend
}

func (info *IRODSServerInfo) GetComposeFilePath() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.Errorf("failed to get current file path")
	}

	currentDir := filepath.Dir(currentFile)

	return fmt.Sprintf("%s/%s", currentDir, info.ComposeFile), nil
}

func (info *IRODSServerInfo) GetAccount() (*types.IRODSAccount, error) {
	account, err := types.CreateIRODSAccount(info.Host, info.Port, info.User, info.Zone, types.AuthScheme(info.AuthScheme), info.Password, info.Resource)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create irods account")
	}

	account.SetCSNegotiation(info.CSNegotiation, info.CSNegotiationPolicy)

	if info.CSNegotiationPolicy == types.CSNegotiationPolicyRequestSSL {
		sslConf := types.IRODSSSLConfig{
			CACertificateFile:       "",
			CACertificatePath:       "",
			EncryptionKeySize:       32,
			EncryptionAlgorithm:     "AES-256-CBC",
			EncryptionSaltSize:      8,
			EncryptionNumHashRounds: 16,
			VerifyServer:            types.SSLVerifyServerNone,
			DHParamsFile:            "",
			ServerName:              "",
		}

		account.SetSSLConfiguration(&sslConf)
	}

	return account, nil
}

func (info *IRODSServerInfo) AddressResolver(address string) string {
	if info.UseAddressResolver {
		return info.Host
	}
	return address
}

func (info *IRODSServerInfo) RequireCompose() bool {
	return len(info.ComposeFile) > 0
}

var (
	TestIRODSServerInfos []IRODSServerInfo = []IRODSServerInfo{
		// 4.2.8 is not supported anymore
		// {
		// 	Name:                "iRODS 4.2.8",
		// 	Version:             "4.2.8",
		// 	AuthScheme:          types.AuthSchemeNative,
		// 	CSNegotiation:       false,
		// 	CSNegotiationPolicy: types.CSNegotiationPolicyRequestTCP,
		// 	ComposeFile:         "irods_4.2.8/docker-compose.yml",

		// 	Host:               testServerHost,
		// 	Port:               testServerPort,
		// 	User:               testServerAdminUser,
		// 	Password:           testServerAdminPassword,
		// 	Zone:               testServerZone,
		// 	Resource:           testServerResource,
		// 	UseAddressResolver: true,

		// 	CacheBackendType: fs.CacheBackendTypeMemory,
		// },
		{
			Name:                "iRODS 4.2.11",
			Version:             "4.2.11",
			AuthScheme:          types.AuthSchemeNative,
			CSNegotiation:       false,
			CSNegotiationPolicy: types.CSNegotiationPolicyRequestTCP,
			ComposeFile:         "irods_4.2.11/docker-compose.yml",

			Host:               testServerHost,
			Port:               testServerPort,
			User:               testServerAdminUser,
			Password:           testServerAdminPassword,
			Zone:               testServerZone,
			Resource:           testServerResource,
			UseAddressResolver: true,

			CacheBackendType: fs.CacheBackendTypeMemory,
		},
		{
			Name:                "iRODS 4.3.3",
			Version:             "4.3.3",
			AuthScheme:          types.AuthSchemeNative,
			CSNegotiation:       false,
			CSNegotiationPolicy: types.CSNegotiationPolicyRequestTCP,
			ComposeFile:         "irods_4.3.3/docker-compose.yml",

			Host:               testServerHost,
			Port:               testServerPort,
			User:               testServerAdminUser,
			Password:           testServerAdminPassword,
			Zone:               testServerZone,
			Resource:           testServerResource,
			UseAddressResolver: true,

			CacheBackendType: fs.CacheBackendTypeMemory,
		},
		{
			Name:                "iRODS 4.3.3 + NoCache",
			Version:             "4.3.3",
			AuthScheme:          types.AuthSchemeNative,
			CSNegotiation:       false,
			CSNegotiationPolicy: types.CSNegotiationPolicyRequestTCP,
			ComposeFile:         "irods_4.3.3/docker-compose.yml",

			Host:               testServerHost,
			Port:               testServerPort,
			User:               testServerAdminUser,
			Password:           testServerAdminPassword,
			Zone:               testServerZone,
			Resource:           testServerResource,
			UseAddressResolver: true,

			CacheBackendType: fs.CacheBackendTypeNone,
		},
		{
			Name:                "iRODS 4.3.3 + Ristretto",
			Version:             "4.3.3",
			AuthScheme:          types.AuthSchemeNative,
			CSNegotiation:       false,
			CSNegotiationPolicy: types.CSNegotiationPolicyRequestTCP,
			ComposeFile:         "irods_4.3.3/docker-compose.yml",

			Host:               testServerHost,
			Port:               testServerPort,
			User:               testServerAdminUser,
			Password:           testServerAdminPassword,
			Zone:               testServerZone,
			Resource:           testServerResource,
			UseAddressResolver: true,

			CacheBackendType: fs.CacheBackendTypeRistretto,
		},
	}
)
