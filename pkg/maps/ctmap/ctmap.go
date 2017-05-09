// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ctmap

import (
	"bytes"
	"fmt"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/op/go-logging"
	"unsafe"
)

var log = logging.MustGetLogger("cilium")

const (
	MapName6       = "cilium_ct6_"
	MapName4       = "cilium_ct4_"
	MapName6Global = MapName6 + "global"
	MapName4Global = MapName4 + "global"

	MapNumEntriesLocal  = 64000
	MapNumEntriesGlobal = 1000000

	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
)

type CtType int

const (
	CtTypeIPv6 CtType = iota
	CtTypeIPv4
	CtTypeIPv6Global
	CtTypeIPv4Global
)

// ServiceKey is the interface describing protocol independent key for services map.
type ServiceKey interface {
	bpf.MapKey

	// Returns human readable string representation
	String() string

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Convert converts fields between host byte order and map byte order if necessary.
	Convert() ServiceKey

	// Dumps contents of key to buffer. Returns true if successful.
	Dump(buffer *bytes.Buffer) bool
}

// ServiceValue is the interface describing protocol independent value for services map.
type ServiceValue interface {
	bpf.MapValue

	// Convert converts fields between host byte order and map byte order if necessary.
	Convert() ServiceValue
}

// CtEntry represents an entry in the connection tracking table.
type CtEntry struct {
	rx_packets uint64
	rx_bytes   uint64
	tx_packets uint64
	tx_bytes   uint64
	lifetime   uint16
	flags      uint16
	revnat     uint16
	proxy_port uint16
}

// GetKeyPtr returns the unsafe.Pointer for s.
func (s *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

// Convert converts s's fields between host bye order and map byte order.
func (s *CtEntry) Convert() ServiceValue {
	n := *s
	n.revnat = common.Swab16(n.revnat)
	return &n
}

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   ServiceKey
	Value CtEntry
}

// ToString iterates through Map m and writes the values of the ct entries in m to a string.
func ToString(m *bpf.Map, mapName string) (string, error) {
	var buffer bytes.Buffer
	entries, err := DumpToSlice(m, mapName)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.Key.Dump(&buffer) {
			continue
		}

		value := entry.Value
		buffer.WriteString(
			fmt.Sprintf(" expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d proxyport=%d\n",
				value.lifetime,
				value.rx_packets,
				value.rx_bytes,
				value.tx_packets,
				value.tx_bytes,
				value.flags,
				common.Swab16(value.revnat),
				common.Swab16(value.proxy_port)),
		)

	}
	return buffer.String(), nil
}

// DumpToSlice iterates through map m and returns a slice mapping each key to its value in m.
func DumpToSlice(m *bpf.Map, mapType string) ([]CtEntryDump, error) {
	entries := []CtEntryDump{}

	switch mapType {
	case MapName6:
		var key, nextKey CtKey6
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)
			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case MapName4:
		var key, nextKey CtKey4
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case MapName6Global:
		var key, nextKey CtKey6Global
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case MapName4Global:
		var key, nextKey CtKey4Global
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}
	}
	return entries, nil
}

// doGC removes key and its corresponding value from Map m if key has a lifetime less than interval. It sets nextKey's address to be the key after key in map m.
// Returns false if there is no other key after key in Map m, and increments deleted if an item is removed from m.
func doGc(m *bpf.Map, interval uint16, key bpf.MapKey, nextKey bpf.MapKey, deleted *int) bool {
	err := m.GetNextKey(key, nextKey)

	// GetNextKey errors out if we have reached the last entry in the map. This signifies that the entire map has been traversed and that garbage collection is done.
	if err != nil {
		return false
	}

	nextEntry, err := m.Lookup(nextKey)

	if err != nil {
		log.Errorf("error during map Lookup: %s", err)
		return false
	}

	entry := nextEntry.(*CtEntry)
	if entry.lifetime <= interval {
		m.Delete(nextKey)
		if err != nil {
			log.Debugf("error during Delete: %s", err)

		}
		(*deleted)++
	} else {
		entry.lifetime -= interval
		m.Update(nextKey, entry)
	}

	return true
}

// GC runs garbage collection for map m with name mapName with interval interval. It returns how many items were deleted from m.
func GC(m *bpf.Map, interval uint16, mapName string) int {
	deleted := 0

	switch mapName {
	case MapName6:
		var key, nextKey CtKey6
		for doGc(m, interval, &key, &nextKey, &deleted) {
			key = nextKey
		}
	case MapName4:
		var key, nextKey CtKey4
		for doGc(m, interval, &key, &nextKey, &deleted) {
			key = nextKey
		}
	case MapName6Global:
		var key, nextKey CtKey6Global
		for doGc(m, interval, &key, &nextKey, &deleted) {
			key = nextKey
		}
	case MapName4Global:
		var key, nextKey CtKey4Global
		for doGc(m, interval, &key, &nextKey, &deleted) {
			key = nextKey
		}
	}
	return deleted
}
