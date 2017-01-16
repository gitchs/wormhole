package http

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

type ProxyServer struct{}

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
		upstream, err = net.Dial("tcp", upstreamAddress)
		if err != nil {
			log.Printf("fail to dial upstream address %s", upstreamAddress)
			http.Error(rw, "fail to dial upstream", http.StatusBadRequest)
			return
		}
		rawConn, _, _ := rw.(http.Hijacker).Hijack()
		rawConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

		defer rawConn.Close()
		defer upstream.Close()

		go io.Copy(upstream, rawConn)
		io.Copy(rawConn, upstream)
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
		upstreamResponse, err = http.DefaultClient.Do(upstreamRequest)
		if err != nil && !strings.Contains(err.Error(), "doNotFollowRedirect") {
			log.Println(err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer upstreamResponse.Body.Close()
		rw.WriteHeader(upstreamResponse.StatusCode)
		for headerKey, headerVals := range upstreamResponse.Header {
			for _, headerVal := range headerVals {
				rw.Header().Set(headerKey, headerVal)
			}
		}
		io.Copy(rw, upstreamResponse.Body)
	}
	return
}

func NewProxyServer() (ps *ProxyServer) {
	ps = new(ProxyServer)
	return
}
