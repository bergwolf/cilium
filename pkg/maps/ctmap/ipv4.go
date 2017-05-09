package ctmap

import (
	"bytes"
	"fmt"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/u8proto"
	"net"
	"unsafe"
)

var (
	// Service4Map is the map representing the bpf local conntrack map.
	Service4Map = bpf.NewMap(MapName4+"_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(CtKey4{})),
		int(unsafe.Sizeof(CtEntry{})),
		MapNumEntriesLocal)

	// Service4GlobalMap is the map representing the bpf global conntrack map.
	Service4GlobalMap = bpf.NewMap(MapName4Global+"services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(CtKey4Global{})),
		int(unsafe.Sizeof(CtEntry{})),
		MapNumEntriesGlobal)
)

//CtKey4 represents the key for IPv4 entries in the local BPF conntrack map.
type CtKey4 struct {
	addr    types.IPv4
	sport   uint16
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// NewCtKey4 creates a CtKey4 with the provided ip, source port, destination port, next header, and flags.
func NewCtKey4(addr net.IP, sport uint16, dport uint16, nexthdr u8proto.U8proto, flags uint8) *CtKey4 {
	key := CtKey4{
		sport:   sport,
		dport:   dport,
		nexthdr: nexthdr,
		flags:   flags,
	}

	copy(key.addr[:], addr.To4())

	return &key
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey4) NewValue() bpf.MapValue { return &CtEntry{} }

// Map returns the BPF map for the local IPv4 conntrack map.
func (k CtKey4) Map() *bpf.Map { return Service4Map }

// Convert converts CtKey4 fields between host bye order and map byte order.
func (k *CtKey4) Convert() ServiceKey {
	n := *k
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey4) String() string {
	return fmt.Sprintf("%s:%d, %d, %d, %d", k.addr, k.sport, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for next header in the key is nonzero.
func (k CtKey4) Dump(buffer *bytes.Buffer) bool {
	if k.nexthdr == 0 {
		return false
	}

	if k.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.nexthdr.String(),
			k.addr.IP().String(),
			k.sport, k.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.nexthdr.String(),
			k.addr.IP().String(),
			k.dport,
			k.sport),
		)
	}

	if k.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}

//CtKey4Global represents the key for IPv4 entries in the global BPF conntrack map.
type CtKey4Global struct {
	daddr   types.IPv4
	saddr   types.IPv4
	sport   uint16
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey4Global) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey4Global) NewValue() bpf.MapValue { return &CtEntry{} }

// Map returns the BPF map for the global IPv4 conntrack map.
func (k CtKey4Global) Map() *bpf.Map { return Service4GlobalMap }

// Convert converts CtKey4Global fields between host bye order and map byte order.
func (k *CtKey4Global) Convert() ServiceKey {
	n := *k
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey4Global) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d, %d, %d", k.saddr, k.sport, k.daddr, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for next header in the key is nonzero.
func (k CtKey4Global) Dump(buffer *bytes.Buffer) bool {
	if k.nexthdr == 0 {
		return false
	}

	if k.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s:%d -> %s:%d ",
			k.nexthdr.String(),
			k.saddr.IP().String(), k.sport,
			k.daddr.IP().String(), k.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s%d -> %s:%d ",
			k.nexthdr.String(),
			k.saddr.IP().String(), k.sport,
			k.daddr.IP().String(), k.dport),
		)
	}

	if k.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}
