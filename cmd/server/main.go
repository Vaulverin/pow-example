package main

import (
	"log"
	"net"

	"golang.org/x/net/netutil"
	"pow-example/internal"
	"pow-example/internal/quotes"
)

func main() {
	addr := internal.GetEnv("WOW_SERVER_ADDR", defaultAddr)
	connLimit := internal.GetEnvInt("WOW_CONN_LIMIT", 5000)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}
	defer func(ln net.Listener) {
		err := ln.Close()
		if err != nil {
			log.Printf("failed to close listener: %v", err)
		}
	}(ln)
	ln = netutil.LimitListener(ln, connLimit)

	log.Printf("Server listening on %s", addr)
	qp := quotes.NewProvider(nil)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn, qp)
	}
}
