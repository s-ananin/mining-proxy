package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// StartPoolDNSCapture observes UDP DNS replies without changing DNS routing.
func StartPoolDNSCapture(tracker *PoolDNS, subnets []string) (func(), error) {
	if len(subnets) == 0 {
		return nil, fmt.Errorf("DNS capture requires allowed_subnets")
	}
	var filters []string
	for _, subnet := range subnets {
		_, network, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, err
		}
		filters = append(filters, "dst net "+network.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	filter := "udp src port 53 and (" + strings.Join(filters, " or ") + ")"
	cmd := exec.CommandContext(ctx, "tcpdump", "-ni", "any", "-p", "--immediate-mode", "-y", "LINUX_SLL", "-s", "0", "-U", "-w", "-", filter)
	cmd.Stderr = os.Stderr
	stream, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		readErr := readPoolDNSCapture(stream, tracker)
		stream.Close()
		waitErr := cmd.Wait()
		if ctx.Err() == nil {
			log.Printf("[DNS] passive capture stopped (pcap: %v, tcpdump: %v)", readErr, waitErr)
		}
	}()
	return func() {
		cancel()
		<-done
	}, nil
}

func readPoolDNSCapture(r io.Reader, tracker *PoolDNS) error {
	var header [24]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	var order binary.ByteOrder = binary.BigEndian
	switch binary.BigEndian.Uint32(header[:4]) {
	case 0xa1b2c3d4:
	case 0xd4c3b2a1:
		order = binary.LittleEndian
	default:
		return fmt.Errorf("unexpected pcap magic")
	}
	if order.Uint32(header[20:]) != 113 { // LINKTYPE_LINUX_SLL
		return fmt.Errorf("unexpected pcap link type")
	}
	packet := make([]byte, 65536+64)
	for {
		if _, err := io.ReadFull(r, header[:16]); err != nil {
			return err
		}
		size := order.Uint32(header[8:12])
		if size > uint32(len(packet)) {
			return fmt.Errorf("oversized pcap record: %d", size)
		}
		if _, err := io.ReadFull(r, packet[:size]); err != nil {
			return err
		}
		source, payload := capturedDNSReply(packet[:size])
		if payload == nil {
			continue
		}
		var reply dns.Msg
		if reply.Unpack(payload) == nil && reply.Response && reply.Opcode == dns.OpcodeQuery && len(reply.Question) == 1 {
			tracker.remember(source, reply.Question[0], &reply, time.Now())
		}
	}
}

// capturedDNSReply extracts the ASIC address and DNS payload from a cooked
// Linux capture. Fragmented packets and IPv6 extension headers are skipped.
func capturedDNSReply(frame []byte) (string, []byte) {
	if len(frame) < 16 {
		return "", nil
	}
	packet := frame[16:]
	var asic net.IP
	var udp []byte
	switch binary.BigEndian.Uint16(frame[14:16]) {
	case 0x0800:
		if len(packet) < 20 || packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return "", nil
		}
		headerLen := int(packet[0]&15) * 4
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLen < 20 || totalLen < headerLen || totalLen > len(packet) {
			return "", nil
		}
		asic, udp = net.IP(packet[16:20]), packet[headerLen:totalLen]
	case 0x86dd:
		if len(packet) < 40 || packet[6] != 17 {
			return "", nil
		}
		totalLen := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if totalLen > len(packet) {
			return "", nil
		}
		asic, udp = net.IP(packet[24:40]), packet[40:totalLen]
	}
	if len(udp) < 8 || binary.BigEndian.Uint16(udp[:2]) != 53 {
		return "", nil
	}
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length <= 8 || length > len(udp) {
		return "", nil
	}
	return asic.String(), udp[8:length]
}
