package httpstream

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"os"
	"time"
)

func Run(packetSource *gopacket.PacketSource, outputPcap string, eventChan chan<- interface{}) error {
	pcapWriter := func(ci gopacket.CaptureInfo, data []byte) error { return nil }
	if outputPcap != "" {
		outPcapFile, err := os.Create(outputPcap)
		if err != nil {
			return err
		}

		defer outPcapFile.Close()
		w := pcapgo.NewWriter(outPcapFile)
		if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
			return err
		}
		pcapWriter = w.WritePacket
	}

	factory := NewFactory(eventChan)
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	count := loop(assembler, packetSource, pcapWriter)
	assembler.FlushAll()
	log.Println("Read pcap file complete")
	factory.Wait()
	log.Println("Parse complete, packet count: ", count)

	close(eventChan)
	return nil
}

type pcapWriterFn func(ci gopacket.CaptureInfo, data []byte) error

func loop(assembler *tcpassembly.Assembler, ps *gopacket.PacketSource, pcapWriter pcapWriterFn) int {
	ticker := time.Tick(time.Minute)

	var lastPacketTimestamp time.Time
	count := 0
	for {
		select {
		case p := <-ps.Packets():
			if p == nil {
				return count
			}

			if v := assemblerTcp(p, pcapWriter, assembler); v != nil {
				lastPacketTimestamp = *v
				count++
			}
		case <-ticker:
			assembler.FlushOlderThan(lastPacketTimestamp.Add(time.Minute * -2))
		}
	}
}

func assemblerTcp(p gopacket.Packet, pcapWriter pcapWriterFn, assembler *tcpassembly.Assembler) *time.Time {
	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil
	}
	transLayer := p.TransportLayer()
	if transLayer == nil {
		return nil
	}
	tcp, _ := transLayer.(*layers.TCP)
	if tcp == nil {
		return nil
	}

	info := p.Metadata().CaptureInfo
	_ = pcapWriter(info, p.Data())
	assembler.AssembleWithTimestamp(netLayer.NetworkFlow(), tcp, info.Timestamp)
	return &info.Timestamp
}
