// Retrieve public PGP keys from the local keyring.
package local

import (
	"bytes"
	"os/exec"

	"golang.org/x/crypto/openpgp"
	"github.com/emersion/go-pgp-pubkey"
)

type source struct {
	cmd string
}

func (s *source) Search(query string) (el openpgp.EntityList, err error) {
	cmd := exec.Command(s.cmd, "--export", query)

	b := &bytes.Buffer{}
	cmd.Stdout = b

	if err = cmd.Run(); err != nil {
		return
	}

	if b.Len() == 0 {
		return
	}

	el, err = openpgp.ReadKeyRing(b)
	return
}

func New() pubkey.Source {
	return &source{"gpg"}
}
