package main

import (
	"crypto/tls"
	"io"
	"net"

	"log"

	"github.com/gitchs/wormhole/utils"
	"github.com/gitchs/wormhole/wormhole-server/initialization"
)

func handleConnection(lc net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
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
	defer func() {
		log.Printf("close client connectino from %s", localConnection.RemoteAddr())
		localConnection.Close()
		if remoteConnection != nil {
			log.Printf("close remote connection for %s", localConnection.RemoteAddr())
			remoteConnection.Close()
		}
	}()
	// 1k buffer for init stage is enough
	buffer := make([]byte, 1024)
	var nread int
	if nread, err = localConnection.Read(buffer); err == nil && nread > 0 {
		var remoteAddress string
		if remoteAddress, err = utils.ParseInitRequest(buffer[0:nread]); err == nil && len(remoteAddress) > 0 {
			buffer = nil
			clientName := localConnection.ConnectionState().PeerCertificates[0].Subject.CommonName
			log.Printf("new tcprelay from [%s](%s) to %s", clientName, localConnection.RemoteAddr(), remoteAddress)
			if remoteConnection, err = net.Dial("tcp", remoteAddress); err == nil {
				localConnection.Write(utils.InitSuccessResponse)
				go io.Copy(localConnection, remoteConnection)
				io.Copy(remoteConnection, localConnection)
			} else {
				localConnection.Write(utils.InitForwardFailResponse)
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
	for {
		var connection net.Conn
		if connection, err = server.Accept(); err != nil {
			continue
		}
		go handleConnection(connection)
	}
}
