package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	irods_fs "github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/go-irodsclient/irods/connection"
	irods_lowlevel_fs "github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/session"
	"github.com/cyverse/go-irodsclient/irods/types"
	"github.com/docker/compose/v2/pkg/api"
	log "github.com/sirupsen/logrus"
	"github.com/testcontainers/testcontainers-go/modules/compose"
)

type IRODSServer struct {
	serverInfo    IRODSServerInfo
	dockerCompose *compose.DockerCompose
	logger        *log.Entry
}

func GetTestIRODSServerInfos() []IRODSServerInfo {
	return TestIRODSServerInfos
}

func NewIRODSServer(serverInfo IRODSServerInfo) *IRODSServer {
	logger := log.StandardLogger().WithFields(log.Fields{
		"name": serverInfo.Name,
	})
	return &IRODSServer{
		serverInfo: serverInfo,
		logger:     logger,
	}
}

func (server *IRODSServer) Start() error {
	if !server.serverInfo.RequireCompose() {
		// Production server
		err := server.waitForPortToOpen(60 * time.Second)
		if err != nil {
			return errors.Wrapf(err, "failed checking port for iRODS server %q", server.serverInfo.Name)
		}
		return nil
	}

	server.logger.Infof("Starting local iRODS server %q", server.serverInfo.Name)

	// disable ryuk
	err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	if err != nil {
		return errors.Wrapf(err, "failed to set environment variable TESTCONTAINERS_RYUK_DISABLED")
	}

	composeFilePath, err := server.serverInfo.GetComposeFilePath()
	if err != nil {
		return errors.Wrapf(err, "failed to get compose file path")
	}

	server.logger.Infof("Using compose file: %s", composeFilePath)

	comp, err := compose.NewDockerCompose(composeFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to create docker compose")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = comp.Up(ctx, compose.WithRecreate(api.RecreateForce), compose.Wait(true))
	if err != nil {
		return errors.Wrapf(err, "failed to start local iRODS server %q", server.serverInfo.Name)
	}

	server.dockerCompose = comp

	// wait
	err = server.waitForPortToOpen(60 * time.Second)
	if err != nil {
		return errors.Wrapf(err, "failed while waiting for port to open for iRODS server %q", server.serverInfo.Name)
	}

	server.logger.Infof("Started local iRODS server %q", server.serverInfo.Name)

	return nil
}

func (server *IRODSServer) Stop() error {
	if server.dockerCompose != nil {
		server.logger.Infof("Stopping local iRODS server %q", server.serverInfo.Name)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := server.dockerCompose.Down(ctx, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
		if err != nil {
			server.logger.Error(errors.Wrapf(err, "failed to stop local iRODS server %q", server.serverInfo.Name))
		}

		// wait
		err = server.waitForPortToClose(60 * time.Second)
		if err != nil {
			server.logger.Error(errors.Wrapf(err, "failed while waiting for port to close for iRODS server %q", server.serverInfo.Name))
			return err
		}

		// give another 10 sec to cleanup
		time.Sleep(10 * time.Second)

		server.logger.Infof("Stopped local iRODS server %q", server.serverInfo.Name)
	}
	return nil
}

func (server *IRODSServer) waitForPortToOpen(timeout time.Duration) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	timeoutChan := time.After(timeout)

	for {
		select {
		case <-timeoutChan:
			return errors.Errorf("timeout waiting for port %d to open", server.serverInfo.Port)
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server.serverInfo.Host, server.serverInfo.Port), 1*time.Second)
			if err == nil {
				// connection succeeded, port is open
				err = conn.Close()
				if err != nil {
					return errors.Wrapf(err, "failed to close test connection for port %d", server.serverInfo.Port)
				}

				// try irods connection
				acc, err := server.GetAccount()
				if err != nil {
					return errors.Wrapf(err, "failed to get irods account")
				}

				connConf := &connection.IRODSConnectionConfig{
					ConnectTimeout:       10 * time.Second,
					OperationTimeout:     30 * time.Second,
					LongOperationTimeout: 60 * time.Second,
					ApplicationName:      server.GetApplicationName(),

					LogEntry: server.logger,
				}

				newConn, err := connection.NewIRODSConnection(acc, connConf)
				if err != nil {
					return errors.Wrapf(err, "failed to create irods connection")
				}

				err = newConn.Connect()
				if err == nil {
					// verify the server is fully ready by stat-ing the home collection
					homeDir, homeDirErr := acc.GetHomeDirPath(), error(nil)
					if homeDir == "" {
						homeDirErr = errors.Errorf("home dir path is empty")
					}

					if homeDirErr == nil {
						_, homeDirErr = irods_lowlevel_fs.GetCollection(newConn, homeDir)
					}

					newConn.Disconnect()

					if homeDirErr == nil {
						return nil
					}

					// collection stat failed, server not fully ready yet
				}

				// connection failed, continue waiting
			}

			// connection failed = port is not open yet
		}
	}
}

func (server *IRODSServer) waitForPortToClose(timeout time.Duration) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	timeoutChan := time.After(timeout)

	for {
		select {
		case <-timeoutChan:
			return errors.Errorf("timeout waiting for port %d to close", server.serverInfo.Port)
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server.serverInfo.Host, server.serverInfo.Port), 1*time.Second)
			if err != nil {
				// connection failed = port is closed
				return nil
			}
			// connection succeeded, port is still open
			err = conn.Close()
			if err != nil {
				return errors.Wrapf(err, "failed to close test connection for port %d", server.serverInfo.Port)
			}
		}
	}
}

func (server *IRODSServer) GetInfo() IRODSServerInfo {
	return server.serverInfo
}

func (server *IRODSServer) GetAccount() (*types.IRODSAccount, error) {
	account, err := server.serverInfo.GetAccount()
	if err != nil {
		return nil, err
	}
	return account, nil
}

func (server *IRODSServer) GetApplicationName() string {
	return "go-irodsclient-test"
}

func (server *IRODSServer) GetConnectionConfig() *connection.IRODSConnectionConfig {
	return &connection.IRODSConnectionConfig{
		ApplicationName: server.GetApplicationName(),
		LogEntry:        server.logger,
	}
}

func (server *IRODSServer) GetFileSystemConfig() *irods_fs.FileSystemConfig {
	fsConfig := irods_fs.NewFileSystemConfig(server.GetApplicationName())
	if server.serverInfo.UseAddressResolver {
		fsConfig.AddressResolver = server.serverInfo.AddressResolver
	}

	// Configure cache backend
	fsConfig.Cache.Backend.Type = irods_fs.CacheBackendType(server.serverInfo.CacheBackendType)

	// Configure Redis if backend is redis
	if server.serverInfo.CacheBackendType == "redis" && server.serverInfo.RedisAddress != "" {
		fsConfig.Cache.Backend.Redis = irods_fs.NewDefaultRedisBackendConfig()
		fsConfig.Cache.Backend.Redis.Address = server.serverInfo.RedisAddress
	}

	fsConfig.LogEntry = server.logger

	return fsConfig
}

func (server *IRODSServer) GetSessionConfig() *session.IRODSSessionConfig {
	fsConfig := server.GetFileSystemConfig()
	return fsConfig.ToIOSessionConfig()
}

func (server *IRODSServer) GetSession() (*session.IRODSSession, error) {
	account, err := server.GetAccount()
	if err != nil {
		return nil, err
	}
	sessionConfig := server.GetSessionConfig()

	return session.NewIRODSSession(account, sessionConfig)
}

func (server *IRODSServer) GetFileSystem() (*irods_fs.FileSystem, error) {
	account, err := server.GetAccount()
	if err != nil {
		return nil, err
	}
	fsConfig := server.GetFileSystemConfig()

	return irods_fs.NewFileSystem(account, fsConfig)
}

func (server *IRODSServer) GetHomeDir() (string, error) {
	account, err := server.GetAccount()
	if err != nil {
		return "", err
	}
	return account.GetHomeDirPath(), nil
}
