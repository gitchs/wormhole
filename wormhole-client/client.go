package main

import (
	"io"
	"net"

	"crypto/tls"

	"github.com/gitchs/wormhole/utils"
	"github.com/gitchs/wormhole/wormhole-client/configure"
	"github.com/golang/glog"
)

// Service forward services
type Service struct {
	LocalAddress  string
	RemoteAddress string
	LocalListener net.Listener
}

// Start start forward service
func (s *Service) Start() {
	glog.Infof("wormhole-client is running on %s, remote server %s will forward all connections to %s", s.LocalAddress, configure.Singleton.RemoteAddress, s.RemoteAddress)
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
			glog.Error(err)
		} else {
			glog.V(4).Info("connection handle successfully")
		}
	}()
	s.realHandler(lc)
}

func (s *Service) realHandler(localConnection net.Conn) {
	var err error
	var remoteConnection *tls.Conn
	glog.V(1).Infof("new connection in from %s", localConnection.RemoteAddr())
	defer func() {
		glog.V(2).Infof("close client connectino from %s", localConnection.RemoteAddr())
		localConnection.Close()
		if remoteConnection != nil {
			glog.V(2).Infof("close remote connection for %s", localConnection.RemoteAddr())
			remoteConnection.Close()
		}
	}()
	tlsConfigure := tls.Config{
		ServerName:   configure.Singleton.TLS.ServerName,
		RootCAs:      configure.CertPool,
		Certificates: []tls.Certificate{configure.TLSCertificate}}
	if remoteConnection, err = tls.Dial("tcp", configure.Singleton.RemoteAddress, &tlsConfigure); err == nil {
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
				glog.Info("fail to connect to remote address")
			default:
				glog.Info("invalid init stage response")
			}
		}
	} else {
		glog.Warningf("fail to connect to remote address %s, %v", s.RemoteAddress, err)
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
	services := make([]*Service, len(configure.Singleton.ForwardServices))
	index := 0
	for localAddress, remoteAddress := range configure.Singleton.ForwardServices {
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
