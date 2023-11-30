package commons

import (
	"net/url"
	"path"
	"strconv"
	"strings"

	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	"github.com/cyverse/irodsfs/commons"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// IRODSAccessURL is used to extract iRODS access information from iRODS Access URL (irods://host:port/zone/path)
type IRODSAccessURL struct {
	User     string
	Password string
	Host     string
	Port     int
	Zone     string
	Path     string
}

// parseIrodsUrl parses iRODS Access URL string and returns IRODSAccessURL struct
func parseIrodsUrl(inputURL string) (*IRODSAccessURL, error) {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "parseIrodsUrl",
	})

	if !strings.HasPrefix(inputURL, "irods://") {
		urlErr := xerrors.Errorf("failed to parse source URL %q", inputURL)
		logger.Errorf("%+v", urlErr)
		return nil, urlErr
	}

	u, err := url.Parse(inputURL)
	if err != nil {
		urlErr := xerrors.Errorf("failed to parse source URL %q: %w", inputURL, err)
		logger.Errorf("%+v", urlErr)
		return nil, urlErr
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

	port := 1247
	if len(u.Port()) > 0 {
		port64, err := strconv.ParseInt(u.Port(), 10, 32)
		if err != nil {
			parseErr := xerrors.Errorf("failed to parse source URL's port number %q: %w", u.Port(), err)
			logger.Errorf("%+v", parseErr)
			return nil, parseErr
		}
		port = int(port64)
	}

	fullpath := path.Clean(u.Path)
	zone := ""
	irodsPath := "/"
	if len(fullpath) == 0 || fullpath[0] != '/' {
		pathErr := xerrors.Errorf("path %q must contain an absolute path", u.Path)
		logger.Errorf("%+v", pathErr)
		return nil, pathErr
	}

	pos := strings.Index(fullpath[1:], "/")
	if pos > 0 {
		zone = strings.Trim(fullpath[1:pos+1], "/")
		irodsPath = fullpath // starts with zone
	} else if pos == -1 {
		// no path
		zone = strings.Trim(fullpath[1:], "/")
		irodsPath = fullpath
	}

	if len(zone) == 0 || len(irodsPath) == 0 {
		pathErr := xerrors.Errorf("path %q must contain an absolute path", inputURL)
		logger.Errorf("%+v", pathErr)
		return nil, pathErr
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

// updateConfigFromIrodsUrl reads info from inputURL and updates config
func updateConfigFromIrodsUrl(inputURL string, config *commons.Config) error {
	logger := log.WithFields(log.Fields{
		"package":  "commons",
		"function": "updateConfigFromIrodsUrl",
	})

	// the inputURL contains irods://HOST:PORT/ZONE/inputPath...
	access, err := parseIrodsUrl(inputURL)
	if err != nil {
		logger.Errorf("%+v", err)
		return err
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

	if len(config.ClientUser) == 0 {
		config.ClientUser = config.ProxyUser
	}

	return nil
}
