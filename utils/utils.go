package utils

import (
	"encoding/binary"
	"errors"
	"net"

	"crypto/tls"

	"github.com/gitchs/wormhole/types/proxy/http"
)

// BuildInitRequest build forward header address
func BuildInitRequest(remoteAddress string) (header []byte) {
	length := len(remoteAddress)
	header = make([]byte, length+2)
	binary.BigEndian.PutUint16(header[0:2], uint16(length))
	copy(header[2:], remoteAddress)
	return
}

// ParseInitRequest parse forward request header
func ParseInitRequest(header []byte) (remoteAddress string, err error) {
	addressLength := binary.BigEndian.Uint16(header[0:2])
	if len(header) == int(addressLength)+2 {
		remoteAddress = string(header[2:])
	} else {
		err = errors.New("invalid forward header")
	}
	return
}

func NewWormholeClientForwardConnectionFactory(server string, tlsConfigure *tls.Config) http.ConnectionFactory {
	var retval = func(network, addr string) (conn net.Conn, err error) {
		switch network {
		case "tcp", "tcp4", "tcp6":

			var rc net.Conn
			rc, err = tls.Dial("tcp", server, tlsConfigure)
			if err == nil {
				initResponseBuffer := make([]byte, 1)
				rc.Write(BuildInitRequest(addr))
				nread, err := rc.Read(initResponseBuffer)
				if err == nil {
					if nread == 1 {
						switch initResponseBuffer[0] {
						case 0:
							conn = rc
						case 1:
							err = errors.New("fail to create forward connection")
						default:
							err = errors.New("invalid init response code")

						}
					} else {
						err = errors.New("invalid wormhole init response")
					}
				}

			}
		default:
			conn, err = net.Dial(network, addr)
		}
		return
	}
	return retval
}

// InitSuccessResponse init success response
var InitSuccessResponse = []byte{0}

// InitForwardFailResponse fail to create forward connection
var InitForwardFailResponse = []byte{1}
