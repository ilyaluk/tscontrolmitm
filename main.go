package main

import (
	"flag"
	"log"
	"net/http"
)

var (
	bindAddr = flag.String("bind-addr", ":8080", "address to bind to")

	stateFile   = flag.String("state-file", "./state.json", "path to file to store state")
	upstreamURL = flag.String("upstream-url", "", "upstream control URL to proxy to")
)

func main() {
	flag.Parse()

	s, err := newState(*stateFile)
	if err != nil {
		log.Fatalf("failed to create state: %v", err)
	}

	if *upstreamURL == "" {
		log.Fatal("-upstream-url is required")
	}
	h, err := newHandler(*upstreamURL, s)
	if err != nil {
		log.Fatalf("failed to create handler: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/key", h.serveKey)
	mux.HandleFunc("/ts2021", h.serveNoise)
	// TODO: handle old /machine/{key} and /machine/{key}/map. Different encryption scheme.

	log.Println("listening on", *bindAddr)
	if err := http.ListenAndServe(*bindAddr, mux); err != http.ErrServerClosed {
		log.Fatalf("failed to listen and serve on %s: %v", *bindAddr, err)
	}
}
