package commons

import (
	"net/url"
	"path"
	"strings"

	"github.com/cockroachdb/errors"
)

func parseRawURL(rawurl string) (string, string, string, error) {
	if len(strings.TrimSpace(rawurl)) == 0 {
		return "", "", "", errors.New("empty raw url")
	}

	u, err := url.ParseRequestURI(rawurl)
	if err != nil || (u.Host == "" && u.Path == "") {
		// try adding //
		u, repErr := url.ParseRequestURI("tcp://" + rawurl)
		if repErr != nil {
			return "", "", "", errors.Wrapf(err, "could not parse raw url %q", rawurl)
		}

		return "tcp", u.Host, "", nil
	}

	if u != nil {
		scheme := strings.ToLower(u.Scheme)
		if scheme == "unix" {
			return "unix", "", u.Path, nil
		} else if scheme == "tcp" {
			return "tcp", u.Host, "", nil
		}

		return u.Scheme, u.Host, u.Path, nil
	}

	return "", "", "", errors.Newf("could not parse raw url %q", rawurl)
}

// ParsePoolServiceEndpoint parses endpoint string
func ParsePoolServiceEndpoint(endpoint string) (string, string, error) {
	scheme, host, p, err := parseRawURL(endpoint)
	if err != nil {
		return "", "", err
	}

	scheme = strings.ToLower(scheme)
	switch scheme {
	case "tcp":
		return "tcp", host, nil
	case "unix":
		p = path.Join("/", strings.TrimPrefix(p, "/"))
		return "unix", p, nil
	case "":
		if len(host) > 0 {
			return "tcp", host, nil
		}
		return "", "", errors.Newf("unknown host %q", host)
	default:
		return "", "", errors.Newf("unsupported protocol %q", scheme)
	}
}
