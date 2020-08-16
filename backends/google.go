package backends

import (
  "context"
  "crypto"
  "crypto/x509"
  "encoding/base64"
  "encoding/pem"
  "io"
  "log"
  "net/http"

  "golang.org/x/crypto/ssh"
  "golang.org/x/oauth2/google"
  "google.golang.org/api/cloudkms/v1"
)


type GoogleBackend struct {
  client *http.Client;
}


type GoogleSigner struct {
  service       *cloudkms.Service
  keyid         string
  publicKey     crypto.PublicKey
}


func NewGoogleBackend() (GoogleBackend) {
  self := GoogleBackend{}
  client, err := google.DefaultClient(context.Background(),
    cloudkms.CloudPlatformScope)
  if err != nil {
    log.Fatal(err)
  }
  self.client = client
  return self
}


func (self *GoogleBackend) configureService(keyid string) (*cloudkms.Service, crypto.PublicKey, error) {
  service, err := cloudkms.New(self.client)
  if err != nil { return nil, nil, err }

  response, err := service.
    Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
    GetPublicKey(keyid).Context(context.Background()).Do()
  if err != nil { return nil, nil, err }

  block, _ := pem.Decode([]byte(response.Pem))
  if block == nil || block.Type != "PUBLIC KEY" { return nil, nil, err }

  publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil { log.Fatal(err) }

  return service, publicKey, nil
}


func sign(service *cloudkms.Service, keyid string, rand io.Reader, digest []byte) ([]byte, error) {
  digest64 := base64.StdEncoding.EncodeToString(digest)
  req := &cloudkms.AsymmetricSignRequest{
    Digest: &cloudkms.Digest{
      Sha256: digest64,
    },
  }
  response, err := service.
    Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
    AsymmetricSign(keyid, req).Context(context.Background()).Do()
  if err != nil {
    return nil, err
  }
  return base64.StdEncoding.DecodeString(response.Signature)
}


func (self *GoogleBackend) GetSecureShellSigner(keyid string) ssh.Signer {
  signer, err := ssh.NewSignerFromSigner(self.GetSigner(keyid))
  if err != nil { log.Fatal(err) }

  return signer
}


func (self *GoogleBackend) GetSigner(keyid string) crypto.Signer {
  service, err := cloudkms.New(self.client)
  if err != nil {
    log.Fatal(err)
  }

  // Fetch the public key from the Google API and decode it.
  response, err := service.
    Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
    GetPublicKey(keyid).Context(context.Background()).Do()
  if err != nil {
    log.Fatal(err)
  }
  block, _ := pem.Decode([]byte(response.Pem))
  if block == nil || block.Type != "PUBLIC KEY" {
    log.Fatal("not a public key")
  }
  publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil {
    log.Fatal(err)
  }

  return &GoogleSigner{
    service   : service,
    keyid     : keyid,
    publicKey : publicKey,
  }
}


func (self *GoogleSigner) Public() crypto.PublicKey {
  return self.publicKey
}


func (self *GoogleSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
  digest64 := base64.StdEncoding.EncodeToString(digest)
  req := &cloudkms.AsymmetricSignRequest{
    Digest: &cloudkms.Digest{
      Sha256: digest64, // TODO: sha256 needs to follow sign algo
    },
  }
  response, err := self.service.
    Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
    AsymmetricSign(self.keyid, req).Context(context.Background()).Do()
  if err != nil {
    log.Fatal(err) // Error here was ignored by the caller.
    return nil, err
  }
  return base64.StdEncoding.DecodeString(response.Signature)
}
