package main

import (
  "bufio"
  "io/ioutil"
  "log"
  "os"

  "github.com/cochiseruhulessin/cloud-pki/x509"
  "github.com/cochiseruhulessin/cloud-pki/backends"
)


func main() {
  var buf []byte
  var err error

  stdin := bufio.NewReader(os.Stdin)
  if (len(os.Args) < 2) {
      os.Exit(1)
  }

  // See if we have input on stdin.
  stat, _ := os.Stdin.Stat()
  if (stat.Mode() & os.ModeCharDevice) == 0 {
    buf, err = ioutil.ReadAll(stdin)
    if err != nil {
      log.Fatal("Error reading from stdin")
    }
  }

  backend := backends.NewGoogleBackend()
  switch op := os.Args[1]; op {
    case "x509":
      x509.Handle(buf, os.Args[2:], &backend)
    default:
      log.Fatal("Unknown operation: ", op)
      os.Exit(1)
  }
}
