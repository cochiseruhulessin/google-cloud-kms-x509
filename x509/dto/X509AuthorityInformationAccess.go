package dto


type X509AuthorityInformationAccess struct {
  OCSP []string `yaml:"ocsp"`
  URLS []string `yaml:"urls"`
}
