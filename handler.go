package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	_ "unsafe"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlclient"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type handler struct {
	upstreamURL string
	state       *state

	dialer *tsdial.Dialer
}

func newHandler(upstreamURL string, state *state) (*handler, error) {
	h := &handler{
		upstreamURL: upstreamURL,
		state:       state,
	}

	mon, err := netmon.New(log.New(os.Stderr, "netmon: ", log.LstdFlags|log.Lmsgprefix).Printf)
	if err != nil {
		return nil, err
	}
	h.dialer = tsdial.NewDialer(mon)

	return h, nil
}

func (h *handler) serveKey(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Query().Get("v") == "" {
		rw.Write([]byte(h.state.legacyKey.Public().UntypedHexString()))
		return
	}

	resp := tailcfg.OverTLSPublicKeyResponse{
		LegacyPublicKey: h.state.legacyKey.Public(),
		PublicKey:       h.state.noiseKey.Public(),
	}

	if err := json.NewEncoder(rw).Encode(resp); err != nil {
		http.Error(rw, "failed to marshal keys", http.StatusInternalServerError)
		return
	}
}

func (h *handler) serveNoise(rw http.ResponseWriter, req *http.Request) {
	log.Println("got noise connection from", req.RemoteAddr)
	logHeaders(log.Default(), req.Header)

	connClient, err := controlhttp.AcceptHTTP(req.Context(), rw, req, h.state.noiseKey, nil)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	defer connClient.Close()

	peerPub := connClient.Peer()
	l := log.New(os.Stderr, peerPub.ShortString()+": ", log.LstdFlags|log.Lmsgprefix)

	l.Println("accepted noise connection")

	priv, err := h.state.lookupMitmKey(peerPub)
	if err != nil {
		l.Println("failed to lookup MITM key:", err)
		return
	}
	l.Println("got MITM key:", priv.Public().ShortString())

	upstreamClient, err := h.getNoiseClient(req.Context(), priv, l.Printf)
	if err != nil {
		l.Println("failed to create upstream noise client:", err)
		return
	}
	defer upstreamClient.Close()
	l.Println("connected to upstream")

	srv := &http2.Server{}
	srv.ServeConn(connClient, &http2.ServeConnOpts{
		Context: req.Context(),
		Handler: &noiseHandler{
			nc:   upstreamClient,
			peer: peerPub,
		},
	})
	l.Println("finished serving noise connection")
}

func (h *handler) getNoiseClient(ctx context.Context, priv key.MachinePrivate, logf logger.Logf) (*controlclient.NoiseClient, error) {
	keysResp, err := loadServerPubKeys(ctx, http.DefaultClient, h.upstreamURL)
	if err != nil {
		return nil, err
	}

	return controlclient.NewNoiseClient(controlclient.NoiseOpts{
		PrivKey:      priv,
		ServerPubKey: keysResp.PublicKey,
		ServerURL:    h.upstreamURL,
		Dialer:       h.dialer,
		DNSCache: &dnscache.Resolver{
			Forward:          net.DefaultResolver,
			LookupIPFallback: nil, // disable DNS fallback via derps bootstrap
			Logf:             logf,
		},
		Logf: logf,
	})
}

//go:linkname loadServerPubKeys tailscale.com/control/controlclient.loadServerPubKeys
func loadServerPubKeys(context.Context, *http.Client, string) (*tailcfg.OverTLSPublicKeyResponse, error)

type noiseHandler struct {
	nc   *controlclient.NoiseClient
	peer key.MachinePublic

	reqId atomic.Int32
}

func (h *noiseHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	id := h.reqId.Add(1)
	l := log.New(os.Stderr, fmt.Sprintf("%s req-%d: ", h.peer.ShortString(), id), log.LstdFlags|log.Lmsgprefix)

	l.Printf("%s %s", req.Method, req.URL.String())
	logHeaders(l, req.Header)

	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		l.Println("failed to read request body:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.URL.Path != "/machine/map" {
		// map polls will be logged in processMapPoll
		logBody(reqBody, "req body", l.Printf)
	}

	req.URL.Scheme = "https"
	req.URL.Host = "unused"
	req.Host = "unused"
	req.RequestURI = ""
	req.Body = io.NopCloser(bytes.NewBuffer(reqBody))

	resp, err := h.nc.Do(req)
	if err != nil {
		l.Println("failed to proxy request:", err)
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	l.Println("upstream response:", resp.Status)
	logHeaders(l, resp.Header)

	for k, v := range resp.Header {
		rw.Header()[k] = v
	}
	rw.WriteHeader(resp.StatusCode)

	if req.URL.Path == "/machine/map" {
		l := log.New(os.Stderr, fmt.Sprintf("%s mappoll-%d: ", h.peer.ShortString(), id), log.LstdFlags|log.Lmsgprefix)
		processMapPoll(reqBody, resp.Body, rw, l.Printf)
		return
	}

	// there is no streaming endpoints besides /machine/map, just read the whole body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		l.Println("failed to read response body:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	logBody(respBody, "resp body", l.Printf)
	rw.Write(respBody)
}

var (
	dumpHeaders = flag.Bool("dump-headers", true, "dump request and response headers")
	dumpBodies  = flag.Bool("dump-bodies", true, "dump request and response bodies")
)

func logHeaders(l *log.Logger, hdr http.Header) {
	if !*dumpHeaders {
		return
	}

	for k, v := range hdr {
		l.Printf("  %s: %v", k, strings.Join(v, ", "))
	}
}

func logBody(body []byte, pfx string, logf logger.Logf) {
	if !*dumpBodies {
		return
	}

	logVal(body, pfx, logf)
}

func logVal(val []byte, pfx string, logf logger.Logf) {
	if len(val) == 0 {
		logf("%s: <empty>", pfx)
		return
	}

	if val[0] == '{' {
		// attempt to pretty-print JSON
		pretty := bytes.NewBuffer(make([]byte, 0, len(val)+256))
		if err := json.Indent(pretty, val, "", "  "); err == nil {
			logf("%s: %s", pfx, pretty)
			return
		}
	}

	logf("%s: %q", pfx, val)
}
