package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

var dumpMapPolls = flag.Bool("dump-mappolls", true, "dump machine map polls")

func processMapPoll(req []byte, src io.Reader, dst http.ResponseWriter, logf logger.Logf) {
	if *dumpMapPolls {
		logVal(req, "req", logf)
	}

	// eh, good enough
	compress := bytes.Contains(req, []byte(`"Compress":"zstd"`))

	for {
		resp, err := readMapResponse(src, compress)
		if err == io.EOF {
			return
		}
		if err != nil {
			logf("readMapResponse: %v", err)
			return
		}

		// Clear out upstream dial plan, it's irrelevant as we mitm.
		resp.ControlDialPlan = nil

		if *dumpMapPolls {
			dump, _ := marshalMapResponse(resp, false)
			logVal(dump, "resp", logf)
		}

		if err := writeMapResponse(dst, resp, compress); err != nil {
			logf("writeMapResponse: %v", err)
			return
		}
		dst.(http.Flusher).Flush()
	}
}

func readMapResponse(r io.Reader, compress bool) (tailcfg.MapResponse, error) {
	respData, err := readLVBytes(r)
	if err != nil {
		return tailcfg.MapResponse{}, err
	}

	return unmarshalMapResponse(respData, compress)
}

var zstdDecoder = must.Get(zstd.NewReader(nil))

func unmarshalMapResponse(respData []byte, compress bool) (tailcfg.MapResponse, error) {
	if compress {
		dec, err := zstdDecoder.DecodeAll(respData, nil)
		if err != nil {
			return tailcfg.MapResponse{}, err
		}
		respData = dec
	}

	var resp tailcfg.MapResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return tailcfg.MapResponse{}, err
	}

	return resp, nil
}

func readLVBytes(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.LittleEndian.Uint32(lenBuf[:])

	if respLen > 1<<20 {
		log.Println("readLVBytes: respLen too large:", respLen)
		return nil, io.ErrUnexpectedEOF
	}

	respData := make([]byte, respLen)
	if _, err := io.ReadFull(r, respData); err != nil {
		return nil, err
	}
	return respData, nil
}

func writeMapResponse(w io.Writer, resp tailcfg.MapResponse, compress bool) error {
	respData, err := marshalMapResponse(resp, compress)
	if err != nil {
		return err
	}

	return writeLVBytes(w, respData)
}

var zstdEncoder = must.Get(zstd.NewWriter(nil))

func marshalMapResponse(resp tailcfg.MapResponse, compress bool) ([]byte, error) {
	respJSON, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	if compress {
		return zstdEncoder.EncodeAll(respJSON, nil), nil
	}

	return respJSON, nil
}

func writeLVBytes(w io.Writer, respData []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(respData)))

	// Writes are buffered, so fine to do them separately:
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(respData)
	return err
}

//func overrideDERPMap(dm *tailcfg.DERPMap, logf logger.Logf) {
//	for id, region := range dm.Regions {
//		logf("region %d: %+v", id, region)
//
//		// We don't mitm STUN, just strip it.
//		region.Nodes = slices.DeleteFunc(region.Nodes, func(n *tailcfg.DERPNode) bool {
//			if n.STUNOnly {
//				logf("  removing STUN-only node: %+v", n)
//			}
//			return n.STUNOnly
//		})
//
//		for i, node := range region.Nodes {
//			logf("  node %d: %+v", i, node)
//
//			// Keep the HostName as-is. We can't override CertName because this will enable cert checking.
//			node.DERPPort = 0 // override just in case
//			if !*secure {
//				node.InsecureForTests = true
//			}
//
//			// Disable captive portal detection, we don't mitm it.
//			node.CanPort80 = false
//
//			node.IPv4 = *bindAddr
//			node.IPv6 = "none" // remove actual ipv6
//
//			// Disable STUN, we don't mitm it.
//			node.STUNPort = -1
//		}
//	}
//}
