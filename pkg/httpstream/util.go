package httpstream

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"os"
)

// NewPacketSource creates a new PacketSource.
// device can be an interface device name or local pcap filename.
func NewPacketSource(device, bpf string) (*gopacket.PacketSource, error) {
	stat, err := os.Stat(device)
	if err == nil && !stat.IsDir() {
		h, err := pcap.OpenOffline(device)
		if err != nil {
			return nil, err
		}
		return gopacket.NewPacketSource(h, h.LinkType()), nil
	}

	if device == "" {
		device = AutoSelectDev()
	}

	h, err := pcap.OpenLive(device, 1024*1024, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if bpf != "" {
		if err = h.SetBPFFilter(bpf); err != nil {
			return nil, err
		}
	}
	return gopacket.NewPacketSource(h, h.LinkType()), nil
}

func AutoSelectDev() string {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return "any"
	}

	for _, i := range ifs {
		for _, j := range i.Addresses {
			if j.IP.IsLoopback() || j.IP.IsMulticast() || j.IP.IsUnspecified() || j.IP.IsLinkLocalUnicast() {
				continue
			}
			return i.Name
		}
	}

	return "any"
}
