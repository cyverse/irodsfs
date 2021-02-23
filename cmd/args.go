package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cyverse/go-irodsclient/client"
	"github.com/cyverse/irodsfs/pkg/irodsfs"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	ChildProcessArgument = "child_process"
)

// IRODSAccessURL ...
type IRODSAccessURL struct {
	User     string
	Password string
	Host     string
	Port     int
	Zone     string
	Path     string
}

func parseIRODSURL(inputURL string) (*IRODSAccessURL, error) {
	u, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}

	user := ""
	password := ""

	if u.User != nil {
		uname := u.User.Username()
		if len(uname) > 0 {
			user = uname
		}

		if pwd, ok := u.User.Password(); ok {
			password = pwd
		}
	}

	host := ""
	host = u.Hostname()

	port := 0
	if len(u.Port()) > 0 {
		port64, err := strconv.ParseInt(u.Port(), 10, 32)
		if err != nil {
			return nil, err
		}
		port = int(port64)
	}

	fullpath := path.Clean(u.Path)
	zone := ""
	irodsPath := "/"
	if len(fullpath) == 0 || fullpath[0] != '/' {
		return nil, fmt.Errorf("path (%s) must contain an absolute path", u.Path)
	}

	pos := strings.Index(fullpath[1:], "/")
	if pos > 0 {
		zone = strings.Trim(fullpath[1:pos+1], "/")
		irodsPath = fullpath[pos+2:]
	} else if pos == -1 {
		// no path
		zone = strings.Trim(fullpath[1:], "/")
	}

	if len(zone) == 0 || len(irodsPath) == 0 {
		return nil, fmt.Errorf("path (%s) must contain an absolute path", inputURL)
	}

	return &IRODSAccessURL{
		User:     user,
		Password: password,
		Host:     host,
		Port:     port,
		Zone:     zone,
		Path:     irodsPath,
	}, nil
}

func makeIRODSZonePath(zone string, path string) string {
	// argument path may not start with zone
	inputPath := path
	zonePath := fmt.Sprintf("/%s/", zone)

	if !strings.HasPrefix(path, zonePath) {
		if strings.HasPrefix(path, "/") {
			inputPath = fmt.Sprintf("/%s%s", zone, path)
		} else {
			inputPath = fmt.Sprintf("/%s/%s", zone, path)
		}
	}
	return inputPath
}

func inputAdditionalParams(config *irodsfs.Config) error {
	if len(config.Host) == 0 {
		fmt.Print("iRODS Hostname: ")
		fmt.Scanln(&config.Host)
	}

	if config.Port == 0 {
		fmt.Print("iRODS Port: ")
		fmt.Scanln(&config.Port)
	}

	if len(config.Zone) == 0 {
		fmt.Print("Zone: ")
		fmt.Scanln(&config.Zone)
	}

	if len(config.ProxyUser) == 0 {
		fmt.Print("Username: ")
		fmt.Scanln(&config.ProxyUser)

		config.ClientUser = config.ProxyUser
	}

	if len(config.Password) == 0 {
		fmt.Print("Password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Print("\n")
		if err != nil {
			return err
		}

		config.Password = string(bytePassword)
	}

	return nil
}

func processArguments() (*irodsfs.Config, error) {
	var version bool
	var irodsAddress string // contains HOST:PORT
	var operationTimeout string
	var connectionIdleTimeout string
	var cacheTimeout string
	var cacheCleanupTime string

	config := irodsfs.NewDefaultConfig()

	// Parse parameters
	flag.BoolVar(&version, "version", false, "Print client version information")
	flag.BoolVar(&version, "v", false, "Print client version information (shorthand form)")
	flag.BoolVar(&config.Foreground, "f", false, "Run in foreground")
	flag.BoolVar(&config.ChildProcess, ChildProcessArgument, false, "")
	flag.StringVar(&config.Host, "host", "", "Set iRODS host address")
	flag.IntVar(&config.Port, "port", 0, "Set iRODS port number")
	flag.StringVar(&irodsAddress, "addr", "", "Set iRODS Address (HOST:PORT)")
	flag.StringVar(&config.ProxyUser, "proxyuser", "", "Set iRODS proxy user")
	flag.StringVar(&config.ClientUser, "clientuser", "", "Set iRODS client user")
	flag.StringVar(&config.ProxyUser, "user", "", "Set iRODS user")
	flag.StringVar(&config.ProxyUser, "u", "", "Set iRODS user (shorthand form)")
	flag.StringVar(&config.Password, "password", "", "Set iRODS client password")
	flag.StringVar(&config.Password, "p", "", "Set iRODS client password (shorthand form)")
	flag.StringVar(&config.Zone, "zone", "", "Set iRODS zone")
	flag.StringVar(&config.Zone, "z", "", "Set iRODS zone (shorthand form)")
	flag.IntVar(&config.BlockSize, "blocksize", irodsfs.BlockSizeDefault, "Set data transfer block size")
	flag.IntVar(&config.ConnectionMax, "connectionmax", irodsfs.ConnectionMaxDefault, "Set max data transfer connections")
	flag.StringVar(&operationTimeout, "operationtimeout", "", "Set filesystem operation timeout")
	flag.StringVar(&connectionIdleTimeout, "connectionidletimeout", "", "Set idle data transfer timeout")
	flag.StringVar(&cacheTimeout, "cachetimeout", "", "Set filesystem cache timeout")
	flag.StringVar(&cacheCleanupTime, "cachecleanuptime", "", "Set filesystem cache cleanup time")

	flag.Parse()

	if version {
		info, err := client.GetVersionJSON()
		if err != nil {
			return nil, err
		}

		fmt.Println(info)
		os.Exit(0)
	}

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	// time
	if len(operationTimeout) > 0 {
		timeout, err := time.ParseDuration(operationTimeout)
		if err != nil {
			return nil, err
		}

		config.OperationTimeout = timeout
	}

	if len(connectionIdleTimeout) > 0 {
		timeout, err := time.ParseDuration(connectionIdleTimeout)
		if err != nil {
			return nil, err
		}

		config.ConnectionIdleTimeout = timeout
	}

	if len(cacheTimeout) > 0 {
		timeout, err := time.ParseDuration(cacheTimeout)
		if err != nil {
			return nil, err
		}

		config.CacheTimeout = timeout
	}

	if len(cacheCleanupTime) > 0 {
		timeout, err := time.ParseDuration(cacheCleanupTime)
		if err != nil {
			return nil, err
		}

		config.CacheCleanupTime = timeout
	}

	// the first argument contains irods://HOST:PORT/ZONE/inputPath...
	irodsInputPath := flag.Arg(0)
	access, err := parseIRODSURL(irodsInputPath)
	if err != nil {
		return nil, err
	}

	if len(access.Host) > 0 {
		config.Host = access.Host
	}

	if access.Port > 0 {
		config.Port = access.Port
	}

	if len(access.User) > 0 {
		config.ProxyUser = access.User
	}

	if len(access.Password) > 0 {
		config.Password = access.Password
	}

	if len(access.Zone) > 0 {
		config.Zone = access.Zone
	}

	if len(access.Path) > 0 {
		config.IRODSPath = access.Path
	}

	if len(config.ClientUser) == 0 {
		config.ClientUser = config.ProxyUser
	}

	err = inputAdditionalParams(config)
	if err != nil {
		return nil, err
	}

	// IRODSPath starts with zone
	config.IRODSPath = makeIRODSZonePath(config.Zone, config.IRODSPath)

	// the second argument is local directory that irodsfs will be mounted
	mountpoint, err := filepath.Abs(flag.Arg(1))
	if err != nil {
		return nil, err
	}

	config.MountPath = mountpoint

	return config, nil
}
