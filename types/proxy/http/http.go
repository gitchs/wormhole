package http

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/gitchs/wormhole/utils"
)

// ProxyServer http proxy server
type ProxyServer struct {
	cf utils.WormholeConnectionFactory
}

func (ps *ProxyServer) newStreamConnection(network, addr string) (conn net.Conn, err error) {
	if ps.cf == nil {
		conn, err = net.Dial(network, addr)
	} else {
		conn, err = ps.cf(network, addr)
	}
	return
}

func (ps *ProxyServer) newHTTPClient() (c *http.Client) {
	if ps.cf == nil {
		c = http.DefaultClient
	} else {
		c = &http.Client{
			Transport: &http.Transport{DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return ps.cf(network, addr)
			}},
		}
	}
	return
}

func (ps *ProxyServer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	// always remove proxy authorization header
	r.Header.Del("Proxy-Authorization")

	var err error

	log.Printf(`handle proxy request [%s] {%s} from %s`, r.Method, r.RequestURI, r.RemoteAddr)

	if r.Method == "CONNECT" {
		// handle CONNECT request
		var upstreamAddress string
		var upstream net.Conn
		upstreamAddress = r.RequestURI
		if !strings.Contains(upstreamAddress, ":") {
			http.Error(rw, "invalid upstream address", http.StatusBadRequest)
			return
		}
		upstream, err = ps.cf("tcp", upstreamAddress)
		if err != nil {
			log.Printf("fail to dial upstream address %s", upstreamAddress)
			http.Error(rw, "fail to dial upstream", http.StatusBadRequest)
			return
		}
		var rawConn net.Conn
		if rawConn, _, err = rw.(http.Hijacker).Hijack(); err != nil {
			log.Printf(`failed to hijack http connection. err %v`, err)
			return
		}
		if _, err = rawConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n")); err != nil {
			log.Printf("failed to send CONNECT command response")
			if err = rawConn.Close(); err != nil {
				log.Printf(`already closed? err %v`, err)
			}
			return
		}

		defer func() {
			log.Println("close connections")
			if err = rawConn.Close(); err != nil {
				log.Printf(`already close connection? err %v`, err)
			}
			if err = upstream.Close(); err != nil {
				log.Printf(`already close connection? err %v`, err)
			}
		}()

		relay := utils.NewTCPRelay(rawConn, upstream)
		if err = relay.Start(); err != nil {
			log.Println(`tcp relay always return nil`)
		}
	} else {
		var upstreamRequest *http.Request
		var upstreamResponse *http.Response
		upstreamRequest, err = http.NewRequest(r.Method, r.RequestURI, r.Body)
		if err != nil {
			log.Printf("invalid http request %v", err)
			http.Error(rw, "invalid http request", http.StatusBadRequest)
			return
		}
		upstreamRequest.Header = r.Header
		upstreamRequest.Header.Del("Proxy-Connection")
		upstreamResponse, err = ps.newHTTPClient().Do(upstreamRequest)
		if err != nil && !strings.Contains(err.Error(), "doNotFollowRedirect") {
			log.Println(err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer func() {
			if err = upstreamResponse.Body.Close(); err != nil {
				log.Printf(`failed to close upstream respnose. error %v`, err)
			}
		}()
		rw.WriteHeader(upstreamResponse.StatusCode)
		for headerKey, headerVals := range upstreamResponse.Header {
			for _, headerVal := range headerVals {
				rw.Header().Set(headerKey, headerVal)
			}
		}
		if _, err = io.Copy(rw, upstreamResponse.Body); err != nil {
			log.Printf(`failed to copy upstream response to cilent. error %v`, err)
		}
	}
	return
}

// NewProxyServer create new http proxy server
func NewProxyServer(df utils.WormholeConnectionFactory) (ps *ProxyServer) {
	ps = new(ProxyServer)
	ps.cf = df
	return
}
