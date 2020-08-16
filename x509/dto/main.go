package dto

import (
  "encoding/asn1"
)


var (
  DEFAULT_EXPIRES = 86400 * 90
  oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
  oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
  oidCAIssuers = asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,2}
  oidCrlDistribution = asn1.ObjectIdentifier{2,5,29,31}
  oidOCSP = asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,1}
  oidCpsURI = asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1}
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)
