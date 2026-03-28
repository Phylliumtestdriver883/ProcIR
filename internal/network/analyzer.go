package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHlpAPI       = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetTcpTable2  = modIPHlpAPI.NewProc("GetExtendedTcpTable")
	procGetUdpTable2  = modIPHlpAPI.NewProc("GetExtendedUdpTable")
)

// ConnInfo holds a network connection associated with a process.
type ConnInfo struct {
	Protocol   string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	State      string
}

// Result holds network analysis results for a process.
type Result struct {
	HasNetwork  bool
	Connections []ConnInfo
	RemoteIPs   []string
	RemotePorts []uint16
	HasPublicIP bool
}

// Analyzer collects and caches network connection info per PID.
type Analyzer struct {
	connsByPID map[uint32][]ConnInfo
}

func NewAnalyzer() *Analyzer {
	a := &Analyzer{
		connsByPID: make(map[uint32][]ConnInfo),
	}
	a.collectTCP()
	a.collectUDP()
	return a
}

// GetByPID returns network info for a given process.
func (a *Analyzer) GetByPID(pid uint32) *Result {
	conns, ok := a.connsByPID[pid]
	if !ok || len(conns) == 0 {
		return &Result{}
	}

	result := &Result{
		HasNetwork:  true,
		Connections: conns,
	}

	seen := make(map[string]bool)
	for _, c := range conns {
		if c.RemoteIP != "" && c.RemoteIP != "0.0.0.0" && c.RemoteIP != "::" && c.RemoteIP != "127.0.0.1" && c.RemoteIP != "::1" {
			if !seen[c.RemoteIP] {
				result.RemoteIPs = append(result.RemoteIPs, c.RemoteIP)
				seen[c.RemoteIP] = true
			}
			if c.RemotePort > 0 {
				result.RemotePorts = append(result.RemotePorts, c.RemotePort)
			}
			if isPublicIP(c.RemoteIP) {
				result.HasPublicIP = true
			}
		}
	}

	return result
}

const (
	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1
	AF_INET                 = 2
	AF_INET6                = 23
)

type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type mibTcp6RowOwnerPid struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

func (a *Analyzer) collectTCP() {
	// IPv4 TCP
	a.collectTCP4()
	// IPv6 TCP
	a.collectTCP6()
}

func (a *Analyzer) collectTCP4() {
	var size uint32
	procGetTcpTable2.Call(0, uintptr(unsafe.Pointer(&size)), 1, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	r, _, _ := procGetTcpTable2.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)
	if r != 0 {
		return
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})
	offset := uintptr(4)

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		conn := ConnInfo{
			Protocol:   "TCP",
			LocalIP:    ipv4ToString(row.LocalAddr),
			LocalPort:  uint16(ntohs(row.LocalPort)),
			RemoteIP:   ipv4ToString(row.RemoteAddr),
			RemotePort: uint16(ntohs(row.RemotePort)),
			State:      tcpStateToString(row.State),
		}
		a.connsByPID[row.OwningPid] = append(a.connsByPID[row.OwningPid], conn)
		offset += rowSize
	}
}

func (a *Analyzer) collectTCP6() {
	var size uint32
	procGetTcpTable2.Call(0, uintptr(unsafe.Pointer(&size)), 1, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	r, _, _ := procGetTcpTable2.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		AF_INET6,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)
	if r != 0 {
		return
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rowSize := unsafe.Sizeof(mibTcp6RowOwnerPid{})
	offset := uintptr(4)

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibTcp6RowOwnerPid)(unsafe.Pointer(&buf[offset]))
		conn := ConnInfo{
			Protocol:   "TCP6",
			LocalIP:    net.IP(row.LocalAddr[:]).String(),
			LocalPort:  uint16(ntohs(row.LocalPort)),
			RemoteIP:   net.IP(row.RemoteAddr[:]).String(),
			RemotePort: uint16(ntohs(row.RemotePort)),
			State:      tcpStateToString(row.State),
		}
		a.connsByPID[row.OwningPid] = append(a.connsByPID[row.OwningPid], conn)
		offset += rowSize
	}
}

type mibUdpRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

func (a *Analyzer) collectUDP() {
	var size uint32
	procGetUdpTable2.Call(0, uintptr(unsafe.Pointer(&size)), 1, AF_INET, UDP_TABLE_OWNER_PID, 0)
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	r, _, _ := procGetUdpTable2.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		AF_INET,
		UDP_TABLE_OWNER_PID,
		0,
	)
	if r != 0 {
		return
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rowSize := unsafe.Sizeof(mibUdpRowOwnerPid{})
	offset := uintptr(4)

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibUdpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		conn := ConnInfo{
			Protocol:  "UDP",
			LocalIP:   ipv4ToString(row.LocalAddr),
			LocalPort: uint16(ntohs(row.LocalPort)),
		}
		a.connsByPID[row.OwningPid] = append(a.connsByPID[row.OwningPid], conn)
		offset += rowSize
	}
}

func ipv4ToString(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF)
}

func ntohs(port uint32) uint32 {
	return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
}

func tcpStateToString(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}

func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		{mustParseCIDR("127.0.0.0/8")},
		{mustParseCIDR("169.254.0.0/16")},
		{mustParseCIDR("fc00::/7")},
		{mustParseCIDR("fe80::/10")},
		{mustParseCIDR("::1/128")},
	}

	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return false
		}
	}
	return true
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}
