package dto

import (
  "crypto/x509"
  "encoding/asn1"
  "encoding/pem"
  "errors"
  "io/ioutil"
  "log"

  "gopkg.in/yaml.v2"
)


type X509ConfigurationDTO struct {
  Defaults X509Defaults `yaml:"defaults"`
  Signer Signer `yaml:"signer"`
  Subject X509Subject
  Constraints CertificateConstraints
  Names CertificateNames `yaml:"names"`
  AuthorityInfoAccess X509AuthorityInformationAccess `yaml:"aia"`
  CRLDistribution X509CRLDistributionPoints `yaml:"crl"`
}


func (self *X509ConfigurationDTO) Load(fp string, buf []byte) error {
  var err error
  if len(buf) > 0 && buf != nil {
    err = self.fromBuf(buf)
  } else {
    err = self.fromFile(fp)
  }
  return err
}


func (self *X509ConfigurationDTO) fromFile(fp string) error {
  var err error
  buf, err := ioutil.ReadFile(fp)
  if err == nil {
    err = self.fromBuf(buf)
  }
  return err
}


func (self *X509ConfigurationDTO) fromBuf(buf []byte) error {
  err := yaml.Unmarshal([]byte(buf), &self)
  if err != nil {
    return err;
  }
  return nil
}


// - The email address SHOULD be in the subjectAltName extension, and SHOULD
//   NOT be in the subject distinguished name (RFC 3850).
func (self *X509ConfigurationDTO) GetSigningRequestTemplate() *x509.CertificateRequest {
  subject := self.Subject.GetSubject()
  template := &x509.CertificateRequest{
    // TODO: This needs to be configurable
    SignatureAlgorithm: x509.SHA256WithRSA,
  }

  if (len(self.Names.DNS) != 0) {
    template.DNSNames = self.Names.DNS
  }

  if (len(self.Names.Email) != 0) {
    template.EmailAddresses = self.Names.Email
  }

  raw, err := asn1.Marshal(subject)
  if err != nil {
    log.Fatal(err)
  }

  template.RawSubject = raw
  return template
}


func (self *X509ConfigurationDTO) GetSignerCertificate() (*x509.Certificate, error) {
  if self.Signer.Certificate == "" {
    return nil, errors.New("No certificate specified for signer.")
  }
  buf, err := ioutil.ReadFile(self.Signer.Certificate)
  if err != nil {
    return nil, err
  }
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse certificate: " + err.Error())
	}
  return crt, nil
}
