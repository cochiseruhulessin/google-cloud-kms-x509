package ssh

import (
  "log"
  "os"

  "github.com/cochiseruhulessin/cloud-pki/backends"
)


func Handle(buf []byte, args []string, backend backends.Backend) {
  if (len(args) < 1) {
      os.Exit(1)
  }
  switch op := args[0]; op {
    case "sign":
      HandleSign(buf, args[1:], backend)
    case "authorized-key":
      HandleAuthorizedKey(buf, args[1:], backend)
    default:
      log.Fatal("Unknown operation: ", op)
      os.Exit(1)
  }
}


