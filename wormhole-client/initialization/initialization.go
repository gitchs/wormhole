package initialization

import (
	// import glog flags
	_ "github.com/golang/glog"

	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"

	cc "github.com/gitchs/wormhole/types/configure/client"
)

var configureFilePath = flag.String("initialization", "./configure.yml", "configure file path")

// Configure wormhole client configures
var Configure *cc.Configure

// TLSCertificate client tls certificate
var TLSCertificate tls.Certificate

// CertPool only contains our CA
var CertPool *x509.CertPool

func init() {
	var err error
	var rawCAContent []byte
	if !flag.Parsed() {
		flag.Parse()
	}
	if Configure, err = cc.LoadConfigureFromPath(*configureFilePath); err != nil {
		panic(err)
	}
	if rawCAContent, err = ioutil.ReadFile(Configure.TLS.CAPath); err != nil {
		panic(err)
	}
	if TLSCertificate, err = tls.LoadX509KeyPair(Configure.TLS.CertPath, Configure.TLS.KeyPath); err != nil {
		panic(err)
	}
	CertPool = x509.NewCertPool()
	if !CertPool.AppendCertsFromPEM(rawCAContent) {
		panic("fail to parse ca content")
	}
}
