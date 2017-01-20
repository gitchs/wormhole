package utils

import (
	"errors"
	"io"
	"net"
	"time"
)

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
		ec.SetDeadline(newDeadline)
		wConn.SetDeadline(newDeadline)
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
	io.Copy(elderConnection{Conn: dst}, elderConnection{Conn: src})
	ch <- 1
}

func (t *TCPRelay) Start() (err error) {
	go relayPipe(t.Remote, t.Local, t.ch)
	go relayPipe(t.Local, t.Remote, t.ch)
	select {
	case <-t.ch:
	}
	return nil
}

func NewTCPRelay(local, remote net.Conn) (relay *TCPRelay) {
	relay = new(TCPRelay)
	relay.Local = elderConnection{Conn: local}
	relay.Remote = elderConnection{Conn: remote}
	relay.ch = make(chan int, 2)
	return
}
