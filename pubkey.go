// Get a PGP public key from various sources
package pubkey

import (
	"golang.org/x/crypto/openpgp"
)

type Source interface {
	Search(query string) (el openpgp.EntityList, err error)
}
