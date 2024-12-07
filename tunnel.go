package main

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20"
)

var GlobalKey []byte

type CipherStream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

func main() {
	listenAddr := flag.String("listenAddr", "127.0.0.1:2000", "")
	remoteAddr := flag.String("remoteAddr", "127.0.0.1:2001", "")
	role := flag.String("role", "A", "A or B")
	secret := flag.String("secret", "", "")
	flag.Parse()

	if *secret == "" {
		fmt.Println("Please specify a secret.")
		return
	}
	GlobalKey = []byte(fmt.Sprintf("%x", md5.Sum([]byte(*secret))))
	fmt.Printf("[%s] -> [%s], role = %s, secret = %s\n", *listenAddr, *remoteAddr, *role, *secret)

	server, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		fmt.Printf("Listen failed: %vn", err)
		return
	}
	for {
		client, err := server.Accept()
		if err != nil {
			fmt.Printf("Accept failed: %v", err)
			continue
		}
		go Relay(client, *remoteAddr, *role)
	}
}

type Chacha20Stream struct {
	key     []byte
	encoder *chacha20.Cipher
	decoder *chacha20.Cipher
	conn    net.Conn
}

func NewChacha20Stream(key []byte, conn net.Conn) (*Chacha20Stream, error) {
	s := &Chacha20Stream{
		key:  key, // should be exactly 32 bytes
		conn: conn,
	}

	var err error
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	s.encoder, err = chacha20.NewUnauthenticatedCipher(s.key, nonce)
	if err != nil {
		return nil, err
	}

	if n, err := s.conn.Write(nonce); err != nil || n != len(nonce) {
		return nil, errors.New("write nonce failed: " + err.Error())
	}
	return s, nil
}

func (s *Chacha20Stream) Read(p []byte) (int, error) {
	if s.decoder == nil {
		nonce := make([]byte, chacha20.NonceSizeX)
		if n, err := io.ReadAtLeast(s.conn, nonce, len(nonce)); err != nil || n != len(nonce) {
			return n, errors.New("can't read nonce from stream: " + err.Error())
		}
		decoder, err := chacha20.NewUnauthenticatedCipher(s.key, nonce)
		if err != nil {
			return 0, errors.New("generate decoder failed: " + err.Error())
		}
		s.decoder = decoder
	}

	n, err := s.conn.Read(p)
	if err != nil || n == 0 {
		return n, err
	}
	dst := make([]byte, n)
	pn := p[:n]
	s.decoder.XORKeyStream(dst, pn)
	copy(pn, dst)
	return n, nil
}

func (s *Chacha20Stream) Write(p []byte) (int, error) {
	dst := make([]byte, len(p))
	s.encoder.XORKeyStream(dst, p)
	return s.conn.Write(dst)
}

func (s *Chacha20Stream) Close() error {
	return s.conn.Close()
}

func Relay(client net.Conn, remoteAddr string, role string) {
	remote, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		client.Close()
		return
	}

	var src, dst CipherStream
	if role == "A" {
		src = client
		dst, err = NewChacha20Stream(GlobalKey, remote)
	} else {
		src, err = NewChacha20Stream(GlobalKey, client)
		dst = remote
	}
	if err != nil {
		src.Close()
		dst.Close()
		return
	}
	Socks5Forward(src, dst)
}

func Socks5Forward(client, target CipherStream) {
	forward := func(src, dest CipherStream) {
		defer src.Close()
		defer dest.Close()
		if _, err := io.Copy(src, dest); err != nil {
			panic("fail to transfer data " + err.Error())
		}
	}

	go forward(client, target)
	go forward(target, client)
}
