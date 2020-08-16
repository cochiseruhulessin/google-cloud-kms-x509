package x509

import (
  "encoding/asn1"
  "log"
  "os"

  "github.com/cochiseruhulessin/cloud-pki/backends"
)


var (
  oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
  oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
  oidCrlDistribution = asn1.ObjectIdentifier{2,5,29,31}
)


func Handle(buf []byte, args []string, backend backends.Backend) {
  if (len(args) < 1) {
      os.Exit(1)
  }
  switch op := args[0]; op {
    case "req":
      CreateCertificateSigningRequest(buf, args[1:], backend)
    case "sign":
      SignCertificate(buf, args[1:], backend)
    default:
      log.Fatal("Unknown operation: ", op)
      os.Exit(1)
  }
}

