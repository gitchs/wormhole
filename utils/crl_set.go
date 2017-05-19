package utils

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type FetchCRL struct {
	sync.RWMutex

	TickTime time.Duration
	url      string
	certList *pkix.CertificateList
	Err      error //ParseCRL Error
}

func NewFetchCRL(tic_time time.Duration, url string) *FetchCRL {
	return &FetchCRL{
		TickTime: tic_time,
		url:      url,
	}
}

//TODO
func (fc *FetchCRL) MatchCRL(ctx context.Context) {
	if err := fc.fetchCRL(); err != nil {
		log.Println("ERROR: ", err)
	}

	go func() {
		for {
			t := int64(fc.TickTime)
			select {
			case <-time.Tick(time.Duration(atomic.LoadInt64(&t))):
				if err := fc.fetchCRL(); err != nil {
					log.Println("ERROR: ", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (fc *FetchCRL) ExecMatchCRL(certs []*x509.Certificate) (bool, error) {
	return fc.compare(certs)
}

func (fc *FetchCRL) compare(certs []*x509.Certificate) (bool, error) {
	fc.RLock()
	defer fc.RUnlock()
	log.Println("certs len: ", len(certs))
	crl := fc.certList

	for _, cert := range certs {
		for _, revoked := range crl.TBSCertList.RevokedCertificates {
			log.Println(revoked.RevocationTime)
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				//Serial number match: intermediate is revoked
				return true, fc.Err
			}
		}
	}
	return false, fc.Err
}

func (fc *FetchCRL) fetchCRL() error {
	fc.Lock()
	defer fc.Unlock()

	resp, err := http.Get(fc.url)
	fmt.Println("fetch CRL...")
	if err != nil {
		return err
	} else if resp.StatusCode >= 300 {
		return errors.New("failed to retrieve CRL")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	fc.certList, fc.Err = x509.ParseCRL(body)
	return fc.Err
}
