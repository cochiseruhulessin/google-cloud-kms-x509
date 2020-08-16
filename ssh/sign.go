package ssh

import (
  "crypto/rand"
  "flag"
  "log"
  "os"

  "golang.org/x/crypto/ssh"

  "github.com/cochiseruhulessin/cloud-pki/backends"
  "github.com/cochiseruhulessin/cloud-pki/x509/dto"
)


func HandleSign(stdin []byte, args []string, backend backends.Backend) {
  var constraints string
  var caConf string

  parser := flag.NewFlagSet("ssh", flag.ExitOnError)
  parser.StringVar(&caConf, "ca", "",
    "specifies the Certificate Authority (CA) configuration file.")
  parser.StringVar(&constraints, "-C", "",
    "specifies a configuration file with constraints.")
  parser.Parse(args)

  if len(stdin) == 0 {
    log.Fatal("Public key must be piped.")
  }
  key, _, _, _, err := ssh.ParseAuthorizedKey(stdin)
  if err != nil { log.Fatal(err) }

  if caConf == "" {
    log.Fatal("The -ca parameter is mandatory.")
  }
  opts := dto.X509ConfigurationDTO{}
  err = opts.Load(caConf, nil)
  if err != nil { log.Fatal(err) }

  SignSshPublicKey(backend, key, &opts.Signer)
  return
}


func SignSshPublicKey(backend backends.Backend, key ssh.PublicKey, ca *dto.Signer) {
  signer, err := NewAlgorithmSignerFromSigner(
    backend.GetSigner(ca.KeyID),
    "rsa-sha2-256")
  if err != nil {
    log.Fatal(err)
  }

  crt := ssh.Certificate{
    Key: key,
    CertType: ssh.UserCert,
    ValidAfter: 0,
    ValidBefore: ssh.CertTimeInfinity,
    ValidPrincipals: []string{"guacd"},
    Serial: 1,
    Permissions: ssh.Permissions{
      CriticalOptions: map[string]string{},
      Extensions:      map[string]string{
        "permit-pty": "",
      },
    },
    Reserved: []byte{},
  }

  crt.SignCert(rand.Reader, signer)
  os.Stdout.Write(ssh.MarshalAuthorizedKey(&crt))
  return
}

