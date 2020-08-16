package backends

import (
  "crypto"

  "golang.org/x/crypto/ssh"
)


type Backend interface {
  GetSigner(string) crypto.Signer
  GetSecureShellSigner(string) ssh.Signer
}
