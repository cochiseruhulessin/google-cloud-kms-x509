package dto

import (
  "crypto/x509"
  "io/ioutil"
  "log"
  "time"

  "gopkg.in/yaml.v2"
)


type CertificateConstraints struct {
  End string `yaml:"expires"`
  Start string `yaml:"nbf"`
  Usage []string `yaml:"usage"`
  ExtendedUsage []string `yaml:"extendedUsage"`
  CA CAConstraints `yaml:"ca"`
}


type CAConstraints struct {
  Issuer bool `yaml:"issuer"`
  PathLength int `yaml:"path-length"`
}


type CertificateNames struct {
  SubjectAlternativeNames []string `yaml:"san"`
  DNS []string `yaml:"dns"`
  Email []string `yaml:"email"`
}


func (self *CertificateConstraints) GetTimeBounds(crt *x509.Certificate, defaults *X509Defaults) {
  expires := DEFAULT_EXPIRES
  if defaults.Expires > 0 {
    expires = defaults.Expires * 86400
  }
  utc, err := time.LoadLocation("Etc/UTC")
  if err != nil {
    log.Fatal(err)
    return
  }
  crt.NotBefore = time.Now().In(utc).Truncate(24 * time.Hour)
  if self.Start != "" {
    crt.NotBefore = getDate(self.Start)
  }
  crt.NotAfter = time.Now().In(utc).
    Add(time.Second * time.Duration(expires))
  if self.End != "" {
    crt.NotAfter = getDate(self.End)
  }
}


func getDate(date string) (time.Time) {
  t, err := time.Parse("2006-01-02T15:04:05Z", date)
  if err != nil {
    log.Fatal(err)
  }
  return t
}


func (self *CertificateConstraints) Load(fp string, buf []byte) error {
  var err error
  if len(buf) > 0 && buf != nil {
    err = self.fromBuf(buf)
  } else {
    err = self.fromFile(fp)
  }
  return err
}


func (self *CertificateConstraints) fromFile(fp string) error {
  var err error
  buf, err := ioutil.ReadFile(fp)
  if err == nil {
    err = self.fromBuf(buf)
  }
  return err
}


func (self *CertificateConstraints) fromBuf(buf []byte) error {
  err := yaml.Unmarshal([]byte(buf), &self)
  if err != nil {
    return err;
  }
  return nil
}
