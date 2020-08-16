package backends

import (
  "crypto"
)


type Backend interface {
  GetSigner(string) crypto.Signer
}
