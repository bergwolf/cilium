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
	// Service6Map is the map representing the bpf local conntrack map.
	Service6Map = bpf.NewMap(MapName6+"_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(CtKey6{})),
		int(unsafe.Sizeof(CtEntry{})),
		MapNumEntriesLocal)

	// Service6GlobalMap is the map representing the bpf global conntrack map.
	Service6GlobalMap = bpf.NewMap(MapName6Global+"services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(CtKey6Global{})),
		int(unsafe.Sizeof(CtEntry{})),
		MapNumEntriesGlobal)
)

//CtKey6 represents the key for IPv6 entries in the local BPF conntrack map.
type CtKey6 struct {
	addr    types.IPv6
	sport   uint16
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// NewCtKey6 creates a CtKey6 with the provided ip, source port, destination port, next header, and flags.
func NewCtKey6(addr net.IP, sport uint16, dport uint16, nexthdr u8proto.U8proto, flags uint8) *CtKey6 {
	key := CtKey6{
		sport:   sport,
		dport:   dport,
		nexthdr: nexthdr,
		flags:   flags,
	}

	copy(key.addr[:], addr.To16())

	return &key
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey6) NewValue() bpf.MapValue { return &CtEntry{} }

// Map returns the BPF map for the local IPv6 conntrack map.
func (k CtKey6) Map() *bpf.Map { return Service6Map }

// Convert converts CtKey6 fields between host bye order and map byte order.
func (k *CtKey6) Convert() ServiceKey {
	n := *k
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey6) String() string {
	return fmt.Sprintf("%s:%d, %d, %d, %d", k.addr, k.sport, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for next header in the key is nonzero.
func (key CtKey6) Dump(buffer *bytes.Buffer) bool {
	if key.nexthdr == 0 {
		return false
	}

	if key.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.sport, key.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.dport,
			key.sport),
		)
	}

	if key.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}

//CtKey6Global represents the key for IPv6 entries in the global BPF conntrack map.
type CtKey6Global struct {
	daddr   types.IPv6
	saddr   types.IPv6
	sport   uint16
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey6Global) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey6Global) NewValue() bpf.MapValue { return &CtEntry{} }

// Map returns the BPF map for the global IPv6 conntrack map.
func (k CtKey6Global) Map() *bpf.Map { return Service6GlobalMap }

// Convert converts CtKey6Global fields between host bye order and map byte order.
func (k *CtKey6Global) Convert() ServiceKey {
	n := *k
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey6Global) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d, %d, %d", k.saddr, k.sport, k.daddr, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for next header in the key is nonzero.
func (k CtKey6Global) Dump(buffer *bytes.Buffer) bool {
	if k.nexthdr == 0 {
		return false
	}

	if k.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN [%s]:%d -> [%s]:%d ",
			k.nexthdr.String(),
			k.saddr.IP().String(), k.sport,
			k.daddr.IP().String(), k.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT [%s]:%d -> [%s]:%d ",
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
