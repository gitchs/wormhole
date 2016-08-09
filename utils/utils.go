package utils

import (
	"encoding/binary"
	"errors"
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

// InitSuccessResponse init success response
var InitSuccessResponse = []byte{0}

// InitForwardFailResponse fail to create forward connection
var InitForwardFailResponse = []byte{1}
