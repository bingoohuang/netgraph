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

func Run(ps *gopacket.PacketSource, outputPcap string, ech chan<- interface{}, snapLen int, onlyRequests bool, onlyMethod string) error {
	pcapWriter, writerCloser, err := createPcapWriter(outputPcap, snapLen)
	if err != nil {
		return err
	}
	defer writerCloser()

	factory := NewFactory(ech, onlyRequests, onlyMethod)
	assembler := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	count := loop(assembler, ps, pcapWriter)
	assembler.FlushAll()
	log.Println("Read pcap writer complete")
	factory.Wait()
	log.Println("Parse complete, packet count: ", count)

	close(ech)
	return nil
}

func loop(assembler *tcpassembly.Assembler, ps *gopacket.PacketSource, pcapWriter pcapWriterFn) int {
	count := 0
	ticker := time.Tick(5 * time.Second)

	for {
		select {
		case p := <-ps.Packets():
			if p == nil { // A nil packet indicates the end of a pcap writer.
				return count
			}

			n, t := p.NetworkLayer(), p.TransportLayer()
			if n == nil || t == nil || t.LayerType() != layers.LayerTypeTCP {
				continue
			}

			_ = pcapWriter(p.Metadata().CaptureInfo, p.Data())
			assembler.AssembleWithTimestamp(n.NetworkFlow(), t.(*layers.TCP), p.Metadata().Timestamp)
			count++
		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(time.Second * -10))
		}
	}
}

func createPcapWriter(outputPcap string, snapLen int) (pcapWriterFn, func(), error) {
	if outputPcap == "" {
		return func(gopacket.CaptureInfo, []byte) error { return nil }, func() {}, nil
	}

	f, err := os.Create(outputPcap)
	if err != nil {
		return nil, nil, err
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(snapLen), layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		return nil, nil, err
	}

	return w.WritePacket, func() { _ = f.Close() }, nil
}

type pcapWriterFn func(ci gopacket.CaptureInfo, data []byte) error
