package x509

import (
  "crypto/x509"
  "crypto/rand"
  "encoding/pem"
  "flag"
  "log"
  "os"

  "github.com/cochiseruhulessin/cloud-pki/backends"
  "github.com/cochiseruhulessin/cloud-pki/x509/dto"
)


func CreateCertificateSigningRequest(buf []byte, args []string, backend backends.Backend) {
  var csrConf string
  var err error

  parser := flag.NewFlagSet("req", flag.ExitOnError)
  parser.StringVar(&csrConf, "r", "",
    "specifies the parameters for the Certificate Signing Request (CSR).")
  parser.Parse(args)

  if csrConf == "" && len(buf) == 0 {
    log.Fatal("Provide the CSR parameters through stdin or with -r.")
  }

  req := dto.X509ConfigurationDTO{}
  err = req.Load(csrConf, buf)
  if err != nil { log.Fatal(err) }

  template := req.GetSigningRequestTemplate()
  req.Signer.AddExtensions(template)

  signer := backend.GetSigner(req.Signer.KeyID)
	out, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
    log.Fatal(err)
	}

	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: out})
}
