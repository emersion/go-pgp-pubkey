// Retrieve public PGP keys from a HKP server, defined in https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00.
package hkp

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/crypto/openpgp"
	"github.com/emersion/go-pgp-pubkey"
)

var (
	ErrLookupNotFound = errors.New("hkp: no server found during lookup")
)

// The server absolute path, defined in section 3.
const absPath = "/pks/lookup"

// Values for the "options" parameter, defined in section 3.2.1.
const (
	optionMachineReadable = "mr"
	optionNoModification = "nm"
)

type source struct {
	url string
	client *http.Client
}

func (s *source) Search(query string) (el openpgp.EntityList, err error) {
	req, err := http.NewRequest(http.MethodGet, s.url + absPath, nil)
	if err != nil {
		return
	}

	v := url.Values{}
	v.Set("op", "get")
	v.Set("options", optionMachineReadable)
	v.Set("search", query)
	req.URL.RawQuery = v.Encode()

	req.Header.Set("Accept", "application/pgp-keys")

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Nothing to do
	case http.StatusNotFound:
		return
	default:
		err = errors.New("hkp: http request failed: "+resp.Status)
		return
	}

	el, err = openpgp.ReadArmoredKeyRing(resp.Body)
	return
}

func New(url string) pubkey.Source {
	return &source{url, &http.Client{}}
}

// Lookup discovers HKP keyservers from a domain name.
func Lookup(name string) (src pubkey.Source, err error) {
	_, addrs, err := net.LookupSRV("hkp", "tcp", name)
	if err != nil {
		return
	}
	if len(addrs) == 0 {
		err = ErrLookupNotFound
		return
	}

	addr := addrs[0]

	proto := "http"
	port := ""
	switch addr.Port {
	case 80:
		// Nothing to do
	case 443:
		proto = "https"
	default:
		port = strconv.Itoa(int(addr.Port))
	}

	url := proto + "://"
	if port == "" {
		url += addr.Target
	} else {
		url += net.JoinHostPort(addr.Target, port)
	}

	src = New(url)
	return
}
