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

	// promisc 混杂模式（英语：promiscuous mode）是指一台机器的网卡能够接收所有经过它的数据流，而不论其目的地址是否是它。
	// 一般计算机网卡都工作在非混杂模式下，此时网卡只接受来自网络端口的目的地址指向自己的数据。当网卡工作在混杂模式下时，
	// 网卡将来自接口的所有数据都捕获并交给相应的驱动程序。网卡的混杂模式一般在网络管理员分析网络数据作为网络故障诊断手段时用到，
	// 同时这个模式也被网络黑客利用来作为网络数据窃听的入口。
	// 在Linux操作系统中设置网卡混杂模式时需要管理员权限。
	// 在Windows操作系统和Linux操作系统中都有使用混杂模式的抓包工具，比如著名的开源软件Wireshark。
	h, err := pcap.OpenLive(device, 65535, false, pcap.BlockForever)
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
			ip := j.IP
			if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				continue
			}
			return i.Name
		}
	}

	return "any"
}

func TryGet(c chan int) int {
	v, _ := TryGet2(c)
	return v
}

func TryGet2(c chan int) (int, bool) {
	select {
	case v := <-c:
		return v, true
	default:
		return 0, false
	}
}

func TryPut(c chan int, v int) bool {
	select {
	case c <- v:
		return true
	default:
		return false
	}
}
