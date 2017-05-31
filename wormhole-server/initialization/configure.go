package initialization

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"

	"log"

	"os"

	"crypto/x509/pkix"

	"time"

	"net/http"

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

// VersionString wormhole-server version string, will be replace when build release version
var VersionString = "[SELF BUILD]"

var CRL *pkix.CertificateList

func updateCRL() {
	if Singleton.TLS.CRLURL == "" {
		return
	}
	for {
		log.Println(`update CRL`)
		httpResponse, errHTTP := http.DefaultClient.Get(Singleton.TLS.CRLURL)
		if errHTTP == nil {
			crlBytes, errReadCRL := ioutil.ReadAll(httpResponse.Body)
			if errReadCRL == nil {
				if crl, errParseCRL := x509.ParseCRL(crlBytes); errParseCRL == nil {
					CRL = crl
				}
			}
			httpResponse.Body.Close()
		}
		time.Sleep(time.Second * 600)
	}
}

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
	go updateCRL()
}
