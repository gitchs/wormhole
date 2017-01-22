package http

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
)

var proxyURL = ""

func getProxy(_ *http.Request) (pu *url.URL, err error) {
	if len(proxyURL) > 0 {
		pu, err = url.Parse(proxyURL)
	} else {
		pu, err = nil, nil
	}
	return
}

func TestProxyServer(t *testing.T) {
	ps := NewProxyServer(nil)
	var ln net.Listener
	var err error
	ln, err = net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Log("fail to create listener")
		t.FailNow()
	}
	server := http.Server{Handler: ps}
	go func() {
		var se error
		if se = server.Serve(ln); se != nil {
			t.Log("fail to start http proxy server")
			t.FailNow()
		}
	}()

	proxyURL = fmt.Sprintf("http://%s", ln.Addr().String())

	ts := http.Transport{Proxy: getProxy}
	httpClient := http.Client{Transport: &ts}
	testCases := []string{
		"http://www.baidu.com/",
		"https://www.baidu.com/",
	}
	for _, tc := range testCases {
		var response *http.Response
		response, err = httpClient.Get(tc)
		if err != nil {
			t.FailNow()
		}
		if response.StatusCode != http.StatusOK {
			t.FailNow()
		}
		if err = response.Body.Close(); err != nil {
			t.Log(`fail to close response`)
			t.FailNow()
		}
	}
	if err = ln.Close(); err != nil {
		t.Logf(`fail to close listener? error %v`, err)
		t.FailNow()
	}
}
