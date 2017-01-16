package main

import (
	"io"
	"net"

	"crypto/tls"

	"log"

	"github.com/gitchs/wormhole/utils"
	"github.com/gitchs/wormhole/wormhole-client/initialization"
)

// Service forward services
type Service struct {
	LocalAddress  string
	RemoteAddress string
	LocalListener net.Listener
}

// Start start forward service
func (s *Service) Start() {
	log.Printf("wormhole-client is running on %s, remote server %s will forward all connections to %s", s.LocalAddress, initialization.Configure.RemoteAddress, s.RemoteAddress)
	for {
		var connection net.Conn
		var err error
		if connection, err = s.LocalListener.Accept(); err == nil {
			go s.handleConnection(connection)
		}
	}
}

func (s *Service) handleConnection(lc net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		} else {
			log.Printf("handle connection for %s successfully", lc.RemoteAddr())
		}
	}()
	s.realHandler(lc)
}

func (s *Service) realHandler(localConnection net.Conn) {
	var err error
	var remoteConnection *tls.Conn
	log.Printf("new connection in from %s", localConnection.RemoteAddr())
	defer func() {
		log.Printf("close client connectino from %s", localConnection.RemoteAddr())
		localConnection.Close()
		if remoteConnection != nil {
			log.Printf("close remote connection for %s", localConnection.RemoteAddr())
			remoteConnection.Close()
		}
	}()
	tlsConfigure := tls.Config{
		ServerName:   initialization.Configure.TLS.ServerName,
		RootCAs:      initialization.CertPool,
		Certificates: []tls.Certificate{initialization.TLSCertificate}}
	if remoteConnection, err = tls.Dial("tcp", initialization.Configure.RemoteAddress, &tlsConfigure); err == nil {
		// send init request
		header := utils.BuildInitRequest(s.RemoteAddress)
		remoteConnection.Write(header)
		// wait init response
		buffer := make([]byte, 32)
		var nread int
		nread, err = remoteConnection.Read(buffer)
		if err == nil && nread > 0 {
			switch buffer[0] {
			case 0:
				// release buffer we don't need
				buffer = nil
				// all green, start forward connection
				go io.Copy(localConnection, remoteConnection)
				io.Copy(remoteConnection, localConnection)
			case 1:
				log.Println("fail to connect to remote address")
			default:
				log.Println("invalid init stage response")
			}
		}
	} else {
		log.Println("fail to connect to remote address %s, %v", s.RemoteAddress, err)
	}
}

// NewService create new service
func NewService(localAddress, remoteAddress string) (s *Service, err error) {
	var l net.Listener
	if l, err = net.Listen("tcp", localAddress); err == nil {
		s = new(Service)
		s.LocalAddress = localAddress
		s.RemoteAddress = remoteAddress
		s.LocalListener = l
	}
	return
}

func main() {
	services := make([]*Service, len(initialization.Configure.ForwardServices))
	index := 0
	for localAddress, remoteAddress := range initialization.Configure.ForwardServices {
		var service *Service
		var err error
		if service, err = NewService(localAddress, remoteAddress); err != nil {
			panic(err)
		}
		go service.Start()
		services[index] = service
		index++
	}
	select {}
}
