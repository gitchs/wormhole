package configure

import (
	// import glog flags
	_ "github.com/golang/glog"

	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"

	"github.com/gitchs/wormhole/wormhole-client/configure/types"
)

var configureFilePath = flag.String("configure", "./configure.yml", "configure file path")

// Singleton wormhole client configures
var Singleton *types.Configure

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
	if Singleton, err = types.LoadConfigureFromPath(*configureFilePath); err != nil {
		panic(err)
	}
	if rawCAContent, err = ioutil.ReadFile(Singleton.TLS.CAPath); err != nil {
		panic(err)
	}
	if TLSCertificate, err = tls.LoadX509KeyPair(Singleton.TLS.CertPath, Singleton.TLS.KeyPath); err != nil {
		panic(err)
	}
	CertPool = x509.NewCertPool()
	if !CertPool.AppendCertsFromPEM(rawCAContent) {
		panic("fail to parse ca content")
	}
}
