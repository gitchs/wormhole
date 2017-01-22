package utils

import "net"

type ConnectionFactory func(network, addr string) (conn net.Conn, err error)
