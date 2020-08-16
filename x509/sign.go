package x509

import (
  "crypto/rand"
  "crypto/x509"
  "encoding/pem"
  "flag"
  "log"
  "os"

  "github.com/cochiseruhulessin/cloud-pki/backends"
  "github.com/cochiseruhulessin/cloud-pki/x509/dto"
)


// Take a CSR from stdin and sign it with the CA profile specified using the
// -ca parameter.
func SignCertificate(buf []byte, args []string, backend backends.Backend) {
  var caConf string
  var constraintsConf string
  var csr *x509.CertificateRequest
  var intConf string
  var issuer *x509.Certificate
  var err error
  var selfSigned bool

  parser := flag.NewFlagSet("sign", flag.ExitOnError)
  parser.StringVar(&caConf, "ca", "",
    "specifies the Certificate Authority (CA) configuration file.")
  parser.StringVar(&intConf, "intermediate", "",
    "specifies the intermediate (CA) configuration file.")
  parser.BoolVar(&selfSigned, "selfsigned", false,
    "indicates that the certificate will be self-signed.")
  parser.StringVar(&constraintsConf, "p", "",
    "specifies a configuration file with constraints.")
  parser.Parse(args)

  if caConf == "" {
    log.Fatal("The -ca parameter is mandatory.")
  }
  opts := dto.X509ConfigurationDTO{}
  err = opts.Load(caConf, nil)
  if err != nil { log.Fatal(err) }

  if len(buf) == 0 {
    log.Fatal("Provide the CSR parameters through stdin.")
  }
  block, _ := pem.Decode(buf)
  if block == nil || block.Type != "CERTIFICATE REQUEST" {
    log.Fatal("failed to decode PEM block containing public key")
  }

  constraints := opts.Constraints
  if constraintsConf != "" {
    err = constraints.Load(constraintsConf, nil)
    if err != nil { log.Fatal(err) }
  }

  csr, err = x509.ParseCertificateRequest(block.Bytes)
  if err != nil { log.Fatal(err) }

  if !selfSigned {
    caIssuer, err := opts.GetSignerCertificate()
    if err != nil { log.Fatal(err) }
    issuer = caIssuer
  } else {
    issuer = &x509.Certificate{}
  }

  builder := CertificateBuilder{
    backend: backend,
    opts: opts,
    issuer: issuer,
    selfSigned: selfSigned,
    constraints: constraints,
  }

  crt, err := builder.FromCSR(csr)
  if err != nil {
    log.Fatal(err)
  }

  // Self-signed certificates and intermediate CAs add their own
  // Authority Information Access extension, end-certificates inherit
  // from the issuer. The -intermediate parameter is used to specify
  // these values for an intermediate CA.
  aia := opts
  if intConf != "" {
    aia = dto.X509ConfigurationDTO{}
    err = aia.Load(intConf, nil)
    if err != nil { log.Fatal(err) }
  }

  if len(aia.CRLDistribution.URLS) > 0 {
    crt.CRLDistributionPoints = aia.CRLDistribution.URLS
  }
  if len(aia.AuthorityInfoAccess.URLS) > 0 {
    crt.IssuingCertificateURL = aia.AuthorityInfoAccess.URLS
  }
  if len(aia.AuthorityInfoAccess.OCSP) > 0 {
    crt.OCSPServer = aia.AuthorityInfoAccess.OCSP
  }

  // If we are self-signing, then the issuer is also the certificate
  // to be signed.
  if selfSigned {
    issuer = crt
  }

  signer := backend.GetSigner(opts.Signer.KeyID)
  der, err := x509.CreateCertificate(rand.Reader, crt, issuer,
    csr.PublicKey, signer)
  if err != nil {
    log.Fatal(err)
  }
  if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
  err != nil {
    log.Fatalf("Failed to write data to cert.pem: %v", err)
  }

  return
}
