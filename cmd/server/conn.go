package main

import (
	"bufio"
	"log"
	"net"
	"strings"
	"time"
)

func handleConn(conn net.Conn, qp QuoteProvider) {
	activeConns.Add(1)
	defer activeConns.Add(-1)
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("failed to close connection from %s: %v", conn.RemoteAddr(), err)
		}
	}(conn)

	err := conn.SetDeadline(time.Now().Add(connReadDeadlineSecs * time.Second))
	if err != nil {
		log.Printf("failed to set deadline for %s: %v", conn.RemoteAddr(), err)
		return
	}
	r := bufio.NewReaderSize(conn, bufSize)

	line, isPrefix, err := r.ReadLine()
	if err != nil || isPrefix || len(line) > maxRequestLineBytes {
		log.Printf("invalid request from %s", conn.RemoteAddr())
		return
	}

	switch strings.ToUpper(strings.TrimSpace(string(line))) {
	case "CHALLENGE":
		handleChallenge(conn)
	case "QUOTE":
		handleQuote(conn, r, qp)
	default:
		log.Printf("unknown command from %s", conn.RemoteAddr())
	}
}
