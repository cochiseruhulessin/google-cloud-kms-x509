package main

import (
  "bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
  "io/ioutil"
	"log"
  "math/big"
  "net/http"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
  "gopkg.in/yaml.v2"
)

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)


type X509CertificateAuthority struct {
    Final bool `yaml:"final"`
}


type X509Subject struct {
    C               string `yaml:"C"`
    ST              string `yaml:"ST"`
    L               string `yaml:"L"`
    O               string `yaml:"O"`
    OU              string `yaml:"OU"`
    CN              string `yaml:"CN"`
    emailAddress    string `yaml:"emailAddress"`
}


type Config struct {
    Subject X509Subject `yaml:"subject"`
}


func loadcsr(fp string) (*x509.CertificateRequest, error) {
	buf, err := ioutil.ReadFile(fp)
	if err != nil {
		log.Fatal(err)
	}
  data, _ := pem.Decode(buf)
  if (data == nil) {
    log.Fatal("Input is not a CSR")
  }
  return x509.ParseCertificateRequest(data.Bytes)
}


func signcsr(fp string, backend CryptoBackend) error {
  csr, err := loadcsr(fp)
	if err != nil {
		log.Fatal(err)
	}

  template := x509.Certificate{
    SerialNumber      : big.NewInt(2019),
    Subject           : csr.Subject,
    Signature         : csr.Signature,
    SignatureAlgorithm: csr.SignatureAlgorithm,

    PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
    PublicKey         : csr.PublicKey,

    KeyUsage          : x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
    IsCA              : true,
    BasicConstraintsValid: true,
  }

  fmt.Printf(template.Subject.CommonName)
  caBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
    &backend.signer.publicKey, backend.signer)
  if err != nil {
    return err
  }

  caPEM := new(bytes.Buffer)
  pem.Encode(caPEM, &pem.Block{
    Type:  "CERTIFICATE",
    Bytes: caBytes,
  })
  return nil;
}


type CryptoBackend struct {
  client *http.Client;
  signer *GoogleKMS;
}


func main() {
    type Parameters struct {
        key string;
        out string;
        in string;
        selfsigned bool;
        x509 Config;
    }

    params := Parameters{}
    parser := flag.NewFlagSet("Manages X.509 PKI", flag.ExitOnError)

    parser.StringVar(&params.key, "key", "", "")
    parser.StringVar(&params.out, "out", "out.csr", "")
    parser.StringVar(&params.in, "in", "out.csr", "")
      if (len(os.Args) < 2) {
          parser.Usage()
          os.Exit(1)
      }
    parser.Parse(os.Args[2:])

    // Setup Google Cloud client.
    client, err := google.DefaultClient(context.Background(), cloudkms.CloudPlatformScope)
    if err != nil {
      log.Fatal(err)
    }

    kmsService, err := cloudkms.New(client)
    if err != nil {
      log.Fatal(err)
    }

    s, err := NewGoogleKMSSigner(kmsService, params.key)
    if err != nil {
      log.Fatal(err)
    }

    backend := &CryptoBackend{
      client: client,
      signer: s,
    }

    switch op := os.Args[1]; op {
      case "sign":
        err = signcsr(params.in, *backend)
        if err != nil {
            log.Fatal(err)
        }
      case "csr":
        data, err := ioutil.ReadFile("csr.yaml")
        if err != nil {
            log.Fatal(err)
        }
        err = yaml.Unmarshal([]byte(data), &params.x509)
        if err != nil {
          log.Fatal(err)
        }

        subj := pkix.Name{
          CommonName:         params.x509.Subject.CN,
          Organization:       []string{params.x509.Subject.O},
          OrganizationalUnit: []string{params.x509.Subject.OU},
          Country:            []string{params.x509.Subject.C},
          Province:           []string{params.x509.Subject.ST},
          Locality:           []string{params.x509.Subject.L},
        }

        rawSubj := subj.ToRDNSequence()
        template := &x509.CertificateRequest{}

        if params.x509.Subject.emailAddress != "" {
          rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
            {Type: oidEmailAddress, Value: params.x509.Subject.emailAddress},
          })

          //template.EmailAddresses = []string{*emailFlag}
        }

        asn1Subj, err := asn1.Marshal(rawSubj)
        if err != nil {
          log.Fatal(err)
        }

        template.RawSubject = asn1Subj

        // TODO Make this a flag or read from s.PublicKey?
        //      https://cloud.google.com/kms/docs/algorithms
        //      https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKeyVersionTemplate
        template.SignatureAlgorithm = x509.SHA256WithRSA // x509.SHA256WithRSAPSS

        f, err := os.Create(params.out)
        if err != nil {
          log.Fatal(err)
        }
        defer f.Close()

        if err := CreateCertificateRequest(f, template, s); err != nil {
          log.Fatal(err)
        }
      default:
        parser.Usage()
        os.Exit(1)
    }
}

func CreateCertificateRequest(w io.Writer, template *x509.CertificateRequest, signer crypto.Signer) error {
	out, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return err
	}

	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: out})
}


type GoogleKMS struct {
	Client        *cloudkms.Service
	keyResourceId string
	publicKey     crypto.PublicKey
}


func NewGoogleKMSSigner(client *cloudkms.Service, keyResourceId string) (*GoogleKMS, error) {
	g := &GoogleKMS{
		keyResourceId: keyResourceId,
		Client:        client,
	}

	err := g.getAsymmetricPublicKey()
	if err != nil {
		return nil, err
	}

	return g, nil
}


// Public returns the Public Key from Google Cloud KMS
func (g *GoogleKMS) Public() crypto.PublicKey {
	return &g.publicKey
}


// Sign calls Google Cloud KMS API and performs AsymmetricSign
func (g *GoogleKMS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// API expects the digest to be base64 encoded
	digest64 := base64.StdEncoding.EncodeToString(digest)

	req := &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{
			Sha256: digest64, // TODO: sha256 needs to follow sign algo
		},
	}

	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricSign(g.keyResourceId, req).Context(context.Background()).Do()
	if err != nil {
		return nil, err
	}

	// The response signature is base64 encoded
	return base64.StdEncoding.DecodeString(response.Signature)
}


// getAsymmetricPublicKey pulls public key from Google Cloud KMS API
func (g *GoogleKMS) getAsymmetricPublicKey() error {
	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(g.keyResourceId).Context(context.Background()).Do()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("not a public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	g.publicKey = publicKey.(*rsa.PublicKey)
	return nil
}
