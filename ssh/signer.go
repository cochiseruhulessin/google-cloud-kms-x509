package ssh

import (
  "golang.org/x/crypto/ssh"

  "github.com/cochiseruhulessin/cloud-pki/backends"
)


type Signer struct {
  backend *backends.Backend

}


func (self *Signer) SignSecureShellCertificate(crt *ssh.Certificate) ([]byte, error) {
  return nil, nil
}


func (self *Signer) loadPublicKeyPem() []byte {
  return nil
}
