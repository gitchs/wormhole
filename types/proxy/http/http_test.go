package http

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
)

var proxyURL = ""

func getProxy(req *http.Request) (*url.URL, error) {
	if len(proxyURL) > 0 {
		return url.Parse(proxyURL)
	} else {
		return nil, nil
	}
}

func TestProxyServer(t *testing.T) {
	ps := NewProxyServer(nil)
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Log("fail to create listener")
		t.FailNow()
	}
	server := http.Server{Handler: ps}
	go server.Serve(ln)

	proxyURL = fmt.Sprintf("http://%s", ln.Addr().String())

	ts := http.Transport{Proxy: getProxy}
	httpClient := http.Client{Transport: &ts}
	testCases := []string{
		"http://www.baidu.com/",
		"https://www.baidu.com/",
	}
	for _, tc := range testCases {

		response, err := httpClient.Get(tc)
		if err != nil {
			t.FailNow()
		}
		if response.StatusCode != http.StatusOK {
			t.FailNow()
		}
		response.Body.Close()
	}
	ln.Close()
}
