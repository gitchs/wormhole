package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/gitchs/wormhole/utils"
	"github.com/gitchs/wormhole/wormhole-server/initialization"
)

var crl = utils.NewRevokedCRL(
	time.Second*time.Duration(initialization.Singleton.CRL.Timeout),
	initialization.Singleton.CRL.Crlurl,
)

func handleConnection(lc net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf(`handle connection failed. error %v`, err)
		} else {
			log.Printf("handle connection for %s successfully", lc.RemoteAddr())
		}
	}()
	realHandler(lc)
}

func realHandler(lc net.Conn) {
	var err error
	var remoteConnection net.Conn
	var localConnection *tls.Conn
	var ok bool
	localConnection, ok = lc.(*tls.Conn)
	if !ok {
		log.Println("localConnection must be *tls.Conn")
		return
	}

	if len(localConnection.ConnectionState().PeerCertificates) == 0 {
		localConnection.Handshake()
	}
	if ok, err := crl.CertIsRevokedCRL(localConnection.ConnectionState().PeerCertificates); err != nil {
		log.Println(err)
	} else if ok {
		err_str := "Serial number match: intermediate is revoked."
		log.Println(err_str)
		localConnection.Close()
		return
	}

	defer func() {
		log.Printf("close client connectino from %s", localConnection.RemoteAddr())
		if err = localConnection.Close(); err != nil {
			log.Printf(`close localConnection failed. error %v`, err)
		}

		if remoteConnection != nil {
			log.Printf("close remote connection for %s", localConnection.RemoteAddr())
			if rce := remoteConnection.Close(); rce != nil {
				log.Printf(`fail to close remoteConnection. error %v`, rce)
			}
		}
	}()
	// 1k buffer for init stage is enough
	buffer := make([]byte, 1024)
	var nr int
	if nr, err = localConnection.Read(buffer); err == nil && nr > 0 {
		var remoteAddress string
		if remoteAddress, err = utils.ParseInitRequest(buffer[0:nr]); err == nil && len(remoteAddress) > 0 {
			clientName := localConnection.ConnectionState().PeerCertificates[0].Subject.CommonName
			log.Printf("new tcprelay from [%s](%s) to %s", clientName, localConnection.RemoteAddr(), remoteAddress)
			if remoteConnection, err = net.Dial("tcp", remoteAddress); err == nil {
				if _, err = localConnection.Write(utils.InitSuccessResponse); err != nil {
					log.Printf(`fail to send InitSuccessResponse to %v`, localConnection.RemoteAddr())
					return
				}
				relay := utils.NewTCPRelay(localConnection, remoteConnection)
				if re := relay.Start(); re != nil {
					log.Printf(`relay should always return nil`)
				}
			} else {
				if _, lwe := localConnection.Write(utils.InitForwardFailResponse); lwe != nil {
					log.Printf(`failed to write wormhole connection InitForwardFailResponse. error %v`, lwe)
					return
				}
				log.Printf("fail to connect to remote address %s for %v", remoteAddress, clientName)
			}
		}
	}
}

func main() {
	var err error
	var server net.Listener
	tlsConfigure := tls.Config{
		Certificates: []tls.Certificate{initialization.TLSCertificate},
		ClientCAs:    initialization.CertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert}
	if server, err = tls.Listen("tcp", initialization.Singleton.LocalAddress, &tlsConfigure); err != nil {
		panic(err)
	}
	log.Printf("server is running on %s", initialization.Singleton.LocalAddress)

	crl.BackgroundRoutinue(context.Background())

	for {
		var connection net.Conn
		if connection, err = server.Accept(); err != nil {
			continue
		}
		go handleConnection(connection)
	}
}
