package ssh

import (
  "crypto"
  "errors"
  "io"

  "golang.org/x/crypto/ssh"
)


// From https://github.com/golang/go/issues/36261
type sshAlgorithmSigner struct {
	algorithm string
	signer    ssh.AlgorithmSigner
}


func (s *sshAlgorithmSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}


func (s *sshAlgorithmSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.SignWithAlgorithm(rand, data, s.algorithm)
}


func NewAlgorithmSignerFromSigner(signer crypto.Signer, algorithm string) (ssh.Signer, error) {
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}
	algorithmSigner, ok := sshSigner.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("unable to cast to ssh.AlgorithmSigner")
	}
	s := sshAlgorithmSigner{
		signer:    algorithmSigner,
		algorithm: algorithm,
	}
	return &s, nil
}
