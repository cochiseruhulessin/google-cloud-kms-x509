package ssh

import (
  "flag"
  "log"
  "os"

  "golang.org/x/crypto/ssh"

  "github.com/cochiseruhulessin/cloud-pki/backends"
  "github.com/cochiseruhulessin/cloud-pki/x509/dto"
)


/**
 * Print the authorized key of the given CA to stdout. 
*/
func HandleAuthorizedKey(buf []byte, args []string, backend backends.Backend) {
  var caConf string
  var err error

  parser := flag.NewFlagSet("authorized-key", flag.ExitOnError)
  parser.StringVar(&caConf, "ca", "",
    "specifies the Certificate Authority (CA) configuration file.")
  parser.Parse(args)

  if caConf == "" {
    log.Fatal("The -ca parameter is mandatory.")
  }
  opts := dto.X509ConfigurationDTO{}
  err = opts.Load(caConf, nil)
  if err != nil {
    log.Fatal(err)
  }

  signer :=  backend.GetSecureShellSigner(opts.Signer.KeyID)
  if err != nil {
    log.Fatal(err)
  }
  os.Stdout.Write(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}
