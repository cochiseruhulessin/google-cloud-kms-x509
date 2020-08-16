package domain

import (
  "crypto/rsa"
  "crypto/sha1"
  "encoding/asn1"
  "log"
)


func publicKeyIdentifier(key *rsa.PublicKey) []byte {
  buf, err := asn1.Marshal(pkcs1PublicKey{
    N: key.N,
    E: key.E,
  })
  if err != nil {
    log.Fatal(err)
  }
  h := sha1.Sum(buf)
  return h[:]
}
