package utils

import "net"

// WormholeConnectionFactory wormhole connection factory
type WormholeConnectionFactory func(network, addr string) (conn net.Conn, err error)
