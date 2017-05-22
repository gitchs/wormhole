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
	"sync/atomic"
	"time"
)

type RevokedCRL struct {
	TickTime time.Duration
	url      string
	certList *pkix.CertificateList
	Err      error //ParseCRL Error
}

func NewRevokedCRL(tic_time time.Duration, url string) *RevokedCRL {
	return &RevokedCRL{
		TickTime: tic_time,
		url:      url,
	}
}

//TODO
func (crl *RevokedCRL) BackgroundRoutinue(ctx context.Context) {
	crl.fetchCRL()

	go func() {
		t := int64(crl.TickTime)
		//gen global
		tic := time.Tick(time.Duration(atomic.LoadInt64(&t)))
		for {
			select {
			case <-tic:
				if err := crl.fetchCRL(); err != nil {
					log.Println("ERROR: ", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (crl *RevokedCRL) CertIsRevokedCRL(certs []*x509.Certificate) (bool, error) {
	return crl.certIsRevokedCRL(certs)
}

// check a cert against a specific CRL. Returns the same bool pair
func (crl *RevokedCRL) certIsRevokedCRL(certs []*x509.Certificate) (bool, error) {
	log.Println("certs len: ", len(certs))
	cl := crl.certList

	for _, cert := range certs {
		for _, revoked := range cl.TBSCertList.RevokedCertificates {
			log.Println(revoked.RevocationTime)
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				//Serial number match: intermediate is revoked
				return true, crl.Err
			}
		}
	}
	return false, crl.Err
}

func (crl *RevokedCRL) fetchCRL() error {
	resp, err := http.Get(crl.url)
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

	crl.certList, crl.Err = x509.ParseCRL(body)
	return crl.Err
}
