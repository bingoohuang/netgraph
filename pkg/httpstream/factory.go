package httpstream

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"sync"
	"sync/atomic"
)

// Factory implements StreamFactory interface for tcpassembly.
type Factory struct {
	runningStream int32
	wg            sync.WaitGroup
	seq           uint
	uniStreams    map[streamKey]*pair
	eventChan     chan<- interface{}
}

// NewFactory create a NewFactory.
func NewFactory(out chan<- interface{}) *Factory {
	return &Factory{
		uniStreams: make(map[streamKey]*pair),
		eventChan:  out,
	}
}

// Wait for all stream exit.
func (f *Factory) Wait() { f.wg.Wait() }

// RunningStreamCount get the running stream count.
func (f *Factory) RunningStreamCount() int32 { return atomic.LoadInt32(&f.runningStream) }

// New creates a Factory.
func (f *Factory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	revkey := streamKey{net: netFlow.Reverse(), tcp: tcpFlow.Reverse()}
	if p, ok := f.uniStreams[revkey]; ok {
		delete(f.uniStreams, revkey)
		p.rspStream = newHTTPStream(streamKey{netFlow, tcpFlow})
		go p.runRsp()
		return p.rspStream
	}

	p := newPair(f.seq, f.eventChan)
	key := streamKey{net: netFlow, tcp: tcpFlow}
	p.reqStream = newHTTPStream(key)
	f.uniStreams[key] = p
	f.seq++
	f.wg.Add(1)
	go f.runReq(p)
	return p.reqStream
}

func (f *Factory) runReq(pair *pair) {
	atomic.AddInt32(&f.runningStream, 1)

	defer f.wg.Done()
	defer func() { atomic.AddInt32(&f.runningStream, -1) }()

	pair.runReq()
}
