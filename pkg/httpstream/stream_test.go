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
	f := NewFactory(eventChan)
	pool := tcpassembly.NewStreamPool(f)
	assembler := tcpassembly.NewAssembler(pool)
	packetCount := 0
	fmt.Println("Run")

	handle, err := pcap.OpenOffline("testdata/dump.pcapng")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		netLayer := packet.NetworkLayer()
		transLayer := packet.TransportLayer()

		if netLayer == nil {
			continue
		}
		if transLayer == nil {
			continue
		}
		packetCount++
		tcp, _ := transLayer.(*layers.TCP)
		assembler.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, packet.Metadata().CaptureInfo.Timestamp)
	}

	assembler.FlushAll()
	f.Wait()
	fmt.Println("packet:", packetCount, "http:", len(eventChan))
}
