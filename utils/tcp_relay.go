package utils

import (
	"errors"
	"io"
	"net"
	"time"
)

// TCPRelay simple tcp relay, will disconnect after 300 seconds if not activate data
type TCPRelay struct {
	Local  net.Conn
	Remote net.Conn
	ch     chan int
}

type elderConnection struct {
	net.Conn
}

const bufferSize = 16 * 1024
const elderConnectionTimeout = 300

func (ec elderConnection) WriteTo(w io.Writer) (n int64, err error) {
	var wConn net.Conn
	var ok bool
	wConn, ok = w.(net.Conn)
	if !ok {
		err = errors.New("Only Accept net.Conn as writer")
		return
	}
	buf := make([]byte, bufferSize)
	for {
		newDeadline := time.Now().Add(time.Second * elderConnectionTimeout)
		if ec.SetDeadline(newDeadline) != nil {
			break
		}
		if wConn.SetDeadline(newDeadline) != nil {
			break
		}
		var nr, nw int
		nr, err = ec.Read(buf)
		if nr > 0 {
			nw, err = wConn.Write(buf[0:nr])
			if err != nil {
				break
			}
			n += int64(nw)
		}
		if err != nil {
			break
		}
	}
	return
}

func relayPipe(dst, src net.Conn, ch chan int) {
	var err error
	if _, err = io.Copy(elderConnection{Conn: dst}, elderConnection{Conn: src}); err == nil {
		ch <- 0
	} else {
		ch <- 1
	}
}

// Start start tcp relay, close both connection if any connection get error
func (t *TCPRelay) Start() (err error) {
	go relayPipe(t.Remote, t.Local, t.ch)
	go relayPipe(t.Local, t.Remote, t.ch)
	<-t.ch
	return nil
}

// NewTCPRelay create new tcp relay
func NewTCPRelay(local, remote net.Conn) (relay *TCPRelay) {
	relay = new(TCPRelay)
	relay.Local = elderConnection{Conn: local}
	relay.Remote = elderConnection{Conn: remote}
	relay.ch = make(chan int, 2)
	return
}
