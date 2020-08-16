package dto

import (
  "crypto/x509"
)


type Signer struct {
  KeyID string `yaml:"keyid"`
  IssuingCertificateURLs []string `yaml:"urls"`
  CRLDistributionPoints []string `yaml:"crls"`
  OCSP []string `yaml:"ocsp"`
  CPS []string `yaml:"cps"`
  Certificate string `yaml:"certificate"`
}


func (self *Signer) AddExtensions(t *x509.CertificateRequest) {
  return
}
