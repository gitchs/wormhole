package main

import (
	"io"
	"net"

	"crypto/tls"

	"log"

	"net/http"

	"time"

	httpProxy "github.com/gitchs/wormhole/types/proxy/http"
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
	var remoteConnection net.Conn
	log.Printf("new connection in from %s, forward it to %s", localConnection.RemoteAddr(), s.RemoteAddress)
	defer func() {
		log.Printf("close client connectino from %s, it was forward to %s", localConnection.RemoteAddr(), s.RemoteAddress)
		localConnection.Close()
		if remoteConnection != nil {
			log.Printf("close remote connection for %s, the remote is %s", localConnection.RemoteAddr(), s.RemoteAddress)
			remoteConnection.Close()
		}
	}()
	tlsConfigure := tls.Config{
		ServerName:   initialization.Configure.TLS.ServerName,
		RootCAs:      initialization.CertPool,
		Certificates: []tls.Certificate{initialization.TLSCertificate}}
	cf := utils.NewWormholeClientForwardConnectionFactory(initialization.Configure.RemoteAddress, &tlsConfigure)
	remoteConnection, err = cf("tcp", s.RemoteAddress)
	if err == nil {
		go io.Copy(localConnection, remoteConnection)
		io.Copy(remoteConnection, localConnection)
	} else {
		log.Printf("fail to connect to remote address %s, %v", s.RemoteAddress, err)
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
	if initialization.Configure.HTTP.Enable {
		httpProxyServer := httpProxy.NewProxyServer(
			utils.NewWormholeClientForwardConnectionFactory(
				initialization.Configure.RemoteAddress, &tls.Config{
					ServerName:   initialization.Configure.TLS.ServerName,
					RootCAs:      initialization.CertPool,
					Certificates: []tls.Certificate{initialization.TLSCertificate}}))
		errCh := make(chan error)
		go func() {
			err := http.ListenAndServe(initialization.Configure.HTTP.Address, httpProxyServer)
			errCh <- err
		}()
		time.AfterFunc(500*time.Millisecond, func() {
			errCh <- nil
		})
		select {
		case err := <-errCh:
			if err == nil {
				log.Printf("http proxy server is running on %s", initialization.Configure.HTTP.Address)
			} else {
				log.Printf("http proxy server failed to run, error %v", err)
			}
		}
		close(errCh)
	}
	select {}
}
