package x509

import (
  "crypto/rsa"
  "crypto/sha1"
  "encoding/asn1"
  "crypto/rand"
  "math/big"
)


type pkcs1PublicKey struct {
	N *big.Int
	E int
}


func GenerateX509Serial() (*big.Int, error) {
  // The maximum value for a serial number in an X.509 certificate is
  // 20-octets, which translates to 2^160 - 1
  max := new(big.Int)
  max.SetString("1461501637330902918203684832716283019655932542975", 10)
  return rand.Int(rand.Reader, max)
}


func GetPublicKeyIdentifier(key *rsa.PublicKey) ([]byte, error) {
  var err error
  buf, err := asn1.Marshal(pkcs1PublicKey{
    N: key.N,
    E: key.E,
  })
  if err != nil {
    return nil, err
  }
  h := sha1.Sum(buf)
  return h[:], nil
}
