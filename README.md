# Cloud PKI

This is my first Go project.


## Building

## Usage

### Creating a Certificate Authority (CA) Hierarchy

The `cloud-pki` tool can set up a hierarchy of certification authorities. The
following steps are required:

1. Create a Certificate Signing Request (CSR) for the root CA and sign it.
3. Do the same for subsequent CAs.

We begin by creating a configuration file for the root CA, `root.yaml`:

```
---
signer:
  backend: google

  # Make sure to add the Resource ID of the key *version*
  keyid: <your KMS key resource id.>

subject:
  CN: My Certificate Authority

defaults:
  expires: 3650

# Note that the below settings are applied to the certifactes that are issued
# by the CA. Since we are self-signing here, these are also self-applied. When
# the root CA is signed, these settings must be updated to reflect the desired
# constraints on intermediate CAs
constraints:
  # If constraints.expires is omitted, then a certificate is valid for the
  # number of days specified in defaults.expires
  expires: "2029-12-31T23:59:59Z"

  # If constraints.nbf is omitted, then the certificate is valid from 00:00
  # on the current day.
  nbf: "2020-06-01T00:00:00Z"
  usage:
  - cRLSign
  - keyCertSign
  ca:
    # A path length of -1 means that it is not constrained.
    path-length: -1
    issuer: true
```

Run the following command to create and sign the CSR:

```
cat root.yaml | ./cloud-pki x509 req  > root.csr
cat root.csr | ./cloud-pki x509 sign --ca root.yaml --selfsigned > root.crt
```

If you have OpenSSL installed, the resulting certificate may be inspected with:

`openssl x509 -noout -text -in root.crt`

The root certificate is now signed. Update `root.yaml` to set the desired
constraints for the intermediate CA:

```
# vim root.yaml
---
signer:
  # ... other settings
  certificate: root.crt

constraints:
  expires: "2029-12-31T23:59:59Z"
  nbf: "2020-06-01T00:00:00Z"
  usage:
  - cRLSign
  - keyCertSign
  ca:
    path-length: 0
    issuer: true
```

Next, place the following content in `intermediate.yaml`:

```
---
signer:
  backend: google
  keyid: <your KMS key resource id for the intermediate CA.>

subject:
  CN: My Intermediate Certificate Authority

defaults:
  expires: 365

constraints:
  usage:
  - digitalSignature
  - keyAgreement
  ca:
    issuer: false
```

Create the CSR and certificate in a single line:

`cat ./intermediate.yaml | ./cloud-pki x509 req | ./cloud-pki x509 sign --ca root.yaml > intermediate.crt`


### Signing OpenSSH Public Keys



## Troubleshooting

- You need to have the `cloudkms.admin` and `cloudkms.publicKeyView` roles
  on the Google Cloud KMS keys that you are using.
