package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type FetchCRL struct {
	sync.Mutex

	CRLSet    map[*tls.Conn]struct{}
	TickTime  time.Duration
	url       string
	closeChan chan *tls.Conn
}

func NewFetchCRL(tic_time time.Duration, url string) *FetchCRL {
	return &FetchCRL{
		CRLSet:    make(map[*tls.Conn]struct{}),
		TickTime:  tic_time,
		url:       url,
		closeChan: make(chan *tls.Conn, 200),
	}
}

//TO DO untreated read adn write locks
func (fc *FetchCRL) MatchCRL(ctx context.Context) {
	go func() {
		for {
			t := int64(fc.TickTime)
			select {
			case <-time.Tick(time.Duration(atomic.LoadInt64(&t))):
				if err := fc.execMatchCRL(); err != nil {
					fmt.Println(err)
				}
			case <-ctx.Done():
				fc.CRLSet = map[*tls.Conn]struct{}{}
				return
			case c := <-fc.closeChan:
				delete(fc.CRLSet, c)
			}
		}
	}()
}

func (fc *FetchCRL) execMatchCRL() error {
	cert_list, err := fc.fetchCRL(fc.url)
	if err != nil {
		fmt.Println(err)
		return err
	}
	for ln, _ := range fc.CRLSet {
		fc.compare(ln, cert_list)
	}
	return nil
}

func (fc *FetchCRL) onceMatchCRL(ln *tls.Conn) error {
	cert_list, err := fc.fetchCRL(fc.url)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fc.compare(ln, cert_list)
	return nil
}

func (fc *FetchCRL) compare(ln *tls.Conn, cert_list *pkix.CertificateList) {
	if cert_list == nil {
		return
	}
	for _, revoked := range cert_list.TBSCertList.RevokedCertificates {
		if ln.ConnectionState().PeerCertificates[0].SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			ln.Write([]byte("intermediate is revoked \n\r"))
			ln.Close()
			return
		}
	}
	return
}

func (fc *FetchCRL) StorageConn(conn *tls.Conn) {
	fc.Lock()
	defer fc.Unlock()
	fc.onceMatchCRL(conn)
	fc.CRLSet[conn] = struct{}{}
}

func (fc *FetchCRL) fetchCRL(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return x509.ParseCRL(body)
}

func (fc *FetchCRL) CloseConn(conn *tls.Conn) {
	fc.closeChan <- conn
}
