package httpstream

import (
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func TestNgnet(t *testing.T) {
	eventChan := make(chan interface{}, 1024)
	f := NewFactory(eventChan, false, "")
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(f))
	packetCount := 0
	fmt.Println("Run")

	handle, err := pcap.OpenOffline("testdata/dump.pcap")
	if err != nil {
		panic(err)
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range ps.Packets() {
		n, t := p.NetworkLayer(), p.TransportLayer()
		if n == nil || t == nil || t.LayerType() != layers.LayerTypeTCP {
			continue
		}
		packetCount++
		assembler.AssembleWithTimestamp(n.NetworkFlow(), t.(*layers.TCP), p.Metadata().CaptureInfo.Timestamp)
	}

	assembler.FlushAll()
	f.Wait()
	fmt.Println("p:", packetCount, "http:", len(eventChan))
}
