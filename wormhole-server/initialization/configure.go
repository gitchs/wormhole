package initialization

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"

	"log"

	"os"

	sc "github.com/gitchs/wormhole/types/configure/server"
)

var configureFilePath = flag.String("configure", "./configure.yml", "configure file path")

// Singleton wormhole server configures
var Singleton *sc.Configure

// TLSCertificate server tls certificate
var TLSCertificate tls.Certificate

// CertPool only contains our CA
var CertPool *x509.CertPool

// versionSwitch if enable, dump version string and exit
var versionSwitch = flag.Bool("v", false, "show version string")

var VersionString = "[SELF BUILD]"

func init() {
	log.SetFlags(log.Llongfile | log.Ltime | log.Ldate | log.LstdFlags)
	var err error
	var rawCAContent []byte
	if !flag.Parsed() {
		flag.Parse()
	}
	if *versionSwitch {
		log.Printf(`wormhole-server version is %s`, VersionString)
		os.Exit(0)
	}
	if Singleton, err = sc.LoadConfigureFromPath(*configureFilePath); err != nil {
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
