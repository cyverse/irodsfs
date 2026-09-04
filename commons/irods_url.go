package commons

import (
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
)

// IRODSAccessURL holds iRODS connection details parsed from an irods:// URL
type IRODSAccessURL struct {
	User     string
	Password string
	Host     string
	Port     int
	Zone     string
	Path     string
}

// ParseIRODSUrl parses an irods:// URL and returns an IRODSAccessURL
func ParseIRODSUrl(inputURL string) (*IRODSAccessURL, error) {
	if !strings.HasPrefix(strings.ToLower(inputURL), "irods://") {
		return nil, errors.Newf("URL must use the irods:// scheme %q", inputURL)
	}

	u, err := url.Parse(inputURL)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse URL %q", inputURL)
	}

	user, password := "", ""
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
	}

	port := 1247
	if portStr := u.Port(); portStr != "" {
		port64, err := strconv.ParseInt(portStr, 10, 32)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid port in URL %q", inputURL)
		}
		port = int(port64)
	}

	fullpath := path.Clean(u.Path)
	if len(fullpath) == 0 || fullpath[0] != '/' {
		return nil, errors.Newf("URL path must be absolute %q", inputURL)
	}

	zone := strings.SplitN(fullpath[1:], "/", 2)[0]
	if zone == "" {
		return nil, errors.Newf("URL path must include a zone %q", inputURL)
	}

	return &IRODSAccessURL{
		User:     user,
		Password: password,
		Host:     u.Hostname(),
		Port:     port,
		Zone:     zone,
		Path:     fullpath,
	}, nil
}
