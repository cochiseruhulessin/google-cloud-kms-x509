package x509

import (
  "crypto/rsa"
  "crypto/x509"
  "fmt"
  "errors"

  "github.com/cochiseruhulessin/cloud-pki/backends"
  "github.com/cochiseruhulessin/cloud-pki/x509/dto"
)


type CertificateBuilder struct {
  backend backends.Backend
  opts dto.X509ConfigurationDTO
  issuer *x509.Certificate
  selfSigned bool
}


func (self *CertificateBuilder) FromCSR(csr *x509.CertificateRequest) (*x509.Certificate, error) {
  var err error
  crt := x509.Certificate{
    PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
    PublicKey: csr.PublicKey,
    RawSubject: csr.RawSubject,
    DNSNames: csr.DNSNames,
    EmailAddresses: csr.EmailAddresses,
    IPAddresses: csr.IPAddresses,
    URIs: csr.URIs,
    ExtraExtensions: csr.Extensions,
  }
  self.opts.Constraints.GetTimeBounds(&crt, &self.opts.Defaults)

  serial, err := GenerateX509Serial()
  if err != nil {
    return nil, err
  }
  crt.SerialNumber = serial

  err = self.setKeyUsage(&crt, self.opts.Constraints.Usage)
  if err != nil {
    return nil, err
  }

  err = self.setExtendedKeyUsage(&crt, self.opts.Constraints.ExtendedUsage)
  if err != nil {
    return nil, err
  }

  ski, err := GetPublicKeyIdentifier(csr.PublicKey.(*rsa.PublicKey))
  if err != nil {
    return nil, err
  }
  crt.SubjectKeyId = ski
  if self.selfSigned {
    crt.AuthorityKeyId = ski
  }

  if self.opts.Constraints.CA.Issuer {
    crt.IsCA = true
    crt.BasicConstraintsValid = true
    if self.opts.Constraints.CA.PathLength > -1 {
      crt.MaxPathLen = self.opts.Constraints.CA.PathLength
      if crt.MaxPathLen == 0 {
        crt.MaxPathLenZero = true
      }
    }
  }

  if !self.selfSigned {
    crt.RawIssuer = self.issuer.RawSubject
  } else {
    crt.RawIssuer = csr.RawSubject
  }

  return &crt, nil
}

func (self *CertificateBuilder) setExtendedKeyUsage(crt *x509.Certificate, usage []string) error {
  for _, u := range usage {
    switch u {
      case "serverAuth":
        crt.ExtKeyUsage = append(crt.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
      default:
        return errors.New(fmt.Sprintf("Invalid extKeyUsage: %s", u))
    }
  }
  return nil
}


func (self *CertificateBuilder) setKeyUsage(crt *x509.Certificate, usage []string) error {
  for _, u := range usage {
    switch u {
      case "digitalSignature":
        crt.KeyUsage |= x509.KeyUsageDigitalSignature
      case "nonRepudiation":
        crt.KeyUsage |= x509.KeyUsageContentCommitment
      case "keyEncipherment":
        crt.KeyUsage |= x509.KeyUsageKeyEncipherment
      case "dataEncipherment":
        crt.KeyUsage |= x509.KeyUsageDataEncipherment
      case "keyAgreement":
        crt.KeyUsage |= x509.KeyUsageKeyAgreement
      case "keyCertSign":
        crt.KeyUsage |= x509.KeyUsageCertSign
      case "cRLSign":
        crt.KeyUsage |= x509.KeyUsageCRLSign
      case "encipherOnly":
        crt.KeyUsage |= x509.KeyUsageEncipherOnly
      case "decipherOnly":
        crt.KeyUsage |= x509.KeyUsageDecipherOnly
      default:
        return errors.New(fmt.Sprintf("Invalid keyUsage: %s", u))
    }
  }
  return nil
}
