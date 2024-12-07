package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

func main() {
	server, err := net.Listen("tcp", ":1080")
	if err != nil {
		fmt.Printf("Listen failed: %v\n", err)
		return
	}

	for {
		client, err := server.Accept()
		if err != nil {
			fmt.Printf("Accept failed: %v", err)
			continue
		}
		go process(client)
	}
}

func process(client net.Conn) {
	if err := Socks5Auth(client); err != nil {
		fmt.Println("auth error:", err)
		client.Close()
		return
	}

	target, err := Socks5Connect(client)
	if err != nil {
		fmt.Println("connect error:", err)
		client.Close()
		return
	}

	Socks5Forward(client, target)
}

func Socks5Auth(client net.Conn) error {
	buf := make([]byte, 256)
	nBytes, err := io.ReadFull(client, buf[:2])
	if err != nil || nBytes != 2 {
		return errors.New("fail to reading header" + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	nBytes, err = io.ReadFull(client, buf[:nMethods])
	if err != nil || nBytes != nMethods {
		return errors.New("fail to reading methods" + err.Error())
	}

	nBytes, err = client.Write([]byte{0x05, 0x00})
	if err != nil || nBytes != 2 {
		return errors.New("Fail to write response" + err.Error())
	}
	return nil
}

func Socks5Connect(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)
	nLen := 4
	nBytes, err := io.ReadFull(client, buf[:nLen])
	if err != nil || nBytes != nLen {
		return nil, errors.New("Fail to read header" + err.Error())
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	addr := ""
	switch atyp {
	case 1:
		nLen = 4
		nBytes, err = io.ReadFull(client, buf[:nLen])
		if err != nil || nBytes != nLen {
			return nil, errors.New("Invalid IPv4 Address" + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3:
		nLen := 1
		nBytes, err = io.ReadFull(client, buf[:nLen])
		if err != nil || nBytes != 4 {
			return nil, errors.New("invalid IPv4 Address" + err.Error())
		}

		nLen = int(buf[0])
		nBytes, err = io.ReadFull(client, buf[:nLen])
		if err != nil || nBytes != nLen {
			return nil, errors.New("invalid Hostname" + err.Error())
		}
		addr = string(buf[:nLen])
	case 4:
		return nil, errors.New("IPv6 has not been supported")
	default:
		return nil, errors.New("invalid atyp")
	}

	nLen = 2
	nBytes, err = io.ReadFull(client, buf[:nLen])
	if nBytes != nLen {
		return nil, errors.New("Fail to read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("Fail to dial dst: " + err.Error())
	}

	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}

	return dest, nil
}

func Socks5Forward(client, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}

	go forward(client, target)
	go forward(target, client)
}
