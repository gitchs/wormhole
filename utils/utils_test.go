package utils

import (
	"log"
	"testing"
)

func TestHeader(t *testing.T) {
	remoteAddress := "www.google.com:80"

	header := BuildInitRequest(remoteAddress)
	parsedRemoteAddress, err := ParseInitRequest(header)
	if err != nil || remoteAddress != parsedRemoteAddress {
		t.Error("fail to extract remote address from header")
	}
	log.Println(header)
}
