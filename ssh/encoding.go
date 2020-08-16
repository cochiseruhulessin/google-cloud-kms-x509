package ssh

import (
  "bytes"
  "encoding/base64"

  "golang.org/x/crypto/ssh"
)


func MarshalCertificate(crt *ssh.Certificate) []byte {
	b := &bytes.Buffer{}
	b.WriteString(crt.Type())
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(crt.Marshal())
	e.Close()
	b.WriteByte('\n')
	return b.Bytes()
}
