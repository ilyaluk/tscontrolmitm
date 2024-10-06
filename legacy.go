package main

import (
	"encoding/json"
	"fmt"
	"io"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func readLegacyMapResponse(r io.Reader, compress bool, priv key.MachinePrivate, pub key.MachinePublic) (tailcfg.MapResponse, error) {
	respData, err := readLVBytes(r)
	if err != nil {
		return tailcfg.MapResponse{}, err
	}

	respDec, ok := priv.OpenFrom(pub, respData)
	if !ok {
		return tailcfg.MapResponse{}, fmt.Errorf("failed to decrypt")
	}

	return unmarshalMapResponse(respDec, compress)
}

func writeLegacyMapResponse(w io.Writer, resp tailcfg.MapResponse, compress bool, priv key.MachinePrivate, pub key.MachinePublic) error {
	respData, err := marshalMapResponse(resp, compress)
	if err != nil {
		return err
	}

	respSealed := priv.SealTo(pub, respData)
	return writeLVBytes(w, respSealed)
}

// naclDecode decrypts message from sender with specified pubKey, then JSON-unmarshalls it
func naclDecode(r io.Reader, v any, priv key.MachinePrivate, pub key.MachinePublic) error {
	msg, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	decrypted, ok := priv.OpenFrom(pub, msg)
	if !ok {
		return fmt.Errorf("failed to decrypt")
	}

	return json.Unmarshal(decrypted, v)
}

// naclEncode JSON-marshals message, then encrypts message for receiver with specified pubKey
func naclEncode(v any, priv key.MachinePrivate, pub key.MachinePublic) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return priv.SealTo(pub, b), nil
}
