package dto

import (
  "crypto/x509/pkix"
  "encoding/asn1"
  "log"

  "github.com/cochiseruhulessin/cloud-pki/x509/oid"
)


type X509Subject struct {
    C               string `yaml:"C"`
    ST              string `yaml:"ST"`
    L               string `yaml:"L"`
    O               string `yaml:"O"`
    OU              string `yaml:"OU"`
    CN              string `yaml:"CN"`
    Email    string `yaml:"emailAddress"`
}


func (self *X509Subject) GetSubject() pkix.RDNSequence {
  name := pkix.Name{}

  if self.CN == "" {
    log.Fatal("Specify at least a common name (CN).")
  }
  name.CommonName = self.CN
  if self.C != "" { name.Country = []string{self.C} }
  if self.ST != "" { name.Province = []string{self.ST} }
  if self.L != "" { name.Locality = []string{self.L} }
  if self.O != "" { name.Organization = []string{self.O} }
  if self.OU != "" { name.OrganizationalUnit = []string{self.OU} }


  subject := name.ToRDNSequence()
  if self.Email != "" {
    subject = append(subject, []pkix.AttributeTypeAndValue{
      {Type: oid.OID_EMAIL, Value: self.Email},
    })
  }

  return subject
}


func (self *X509Subject) GetRawSubject() []byte {
  subject := self.GetSubject()
  raw, err := asn1.Marshal(subject)
  if err != nil {
    log.Fatal(err)
  }
  return raw
}
