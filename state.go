package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"tailscale.com/types/key"
)

type state struct {
	path string

	legacyKey, noiseKey key.MachinePrivate

	mu sync.Mutex
	// machinesMitmKeys is a map of public machine keys to their corresponding private keys.
	// Key is client's public key, value is our MITM private key which we use to communicate
	// with the control plane.
	machinesMitmKeys map[key.MachinePublic]key.MachinePrivate
}

type stateJson struct {
	Legacy string
	Noise  string

	MachinesMitmKeys map[string]string
}

func newState(path string) (*state, error) {
	s := &state{
		path: path,

		machinesMitmKeys: make(map[key.MachinePublic]key.MachinePrivate),
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Print("state file does not exist, creating new")

		s.legacyKey = key.NewMachine()
		s.noiseKey = key.NewMachine()

		// no need to lock in constructor
		if err := s.dumpLocked(); err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		var state stateJson
		if err := json.NewDecoder(f).Decode(&state); err != nil {
			return nil, err
		}

		if err := s.legacyKey.UnmarshalText([]byte(state.Legacy)); err != nil {
			return nil, err
		}

		if err := s.noiseKey.UnmarshalText([]byte(state.Noise)); err != nil {
			return nil, err
		}

		for k, v := range state.MachinesMitmKeys {
			pub := key.MachinePublic{}
			if err := pub.UnmarshalText([]byte(k)); err != nil {
				return nil, err
			}

			priv := key.MachinePrivate{}
			if err := priv.UnmarshalText([]byte(v)); err != nil {
				return nil, err
			}

			s.machinesMitmKeys[pub] = priv
		}
		log.Printf("loaded %d keys from state", len(s.machinesMitmKeys))
	}

	return s, nil
}

func (s *state) lookupMitmKey(pub key.MachinePublic) (key.MachinePrivate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if k, ok := s.machinesMitmKeys[pub]; ok {
		return k, nil
	}

	log.Printf("got new machine %v, generating MITM key", pub.ShortString())
	s.machinesMitmKeys[pub] = key.NewMachine()

	if err := s.dumpLocked(); err != nil {
		return key.MachinePrivate{}, err
	}

	return s.machinesMitmKeys[pub], nil
}

// dumpLocked writes the state to disk.
func (s *state) dumpLocked() error {
	var state stateJson

	buf, _ := s.legacyKey.MarshalText()
	state.Legacy = string(buf)

	buf, _ = s.noiseKey.MarshalText()
	state.Noise = string(buf)

	state.MachinesMitmKeys = make(map[string]string)
	for k, v := range s.machinesMitmKeys {
		buf, _ := v.MarshalText()
		state.MachinesMitmKeys[k.String()] = string(buf)
	}

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(state)
}
