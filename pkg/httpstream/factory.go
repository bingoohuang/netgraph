package httpstream

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"sync"
	"sync/atomic"
)

// Factory implements StreamFactory interface for tcpassembly.
type Factory struct {
	runningStream  int32
	wg             sync.WaitGroup
	seq            uint
	uniStreams     map[streamKey]*pair
	uniStreamsLock sync.Mutex
	eventChan      chan<- interface{}
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
	key := streamKey{net: netFlow, tcp: tcpFlow}
	stream := newHTTPStream(key)
	f.wg.Add(1)
	revkey := streamKey{net: netFlow.Reverse(), tcp: tcpFlow.Reverse()}

	f.uniStreamsLock.Lock()
	defer f.uniStreamsLock.Unlock()

	if p, ok := f.uniStreams[revkey]; ok {
		delete(f.uniStreams, revkey)
		go p.run(&f.wg, stream)
		return stream
	}

	p := newPair(f.seq, f.eventChan)
	f.uniStreams[key] = p
	f.seq++

	go func() {
		defer Count(&f.runningStream)()
		defer f.DeleteUniStream(key)

		p.run(&f.wg, stream)
	}()

	return stream
}

func (f *Factory) DeleteUniStream(key streamKey) {
	f.uniStreamsLock.Lock()
	delete(f.uniStreams, key)
	f.uniStreamsLock.Unlock()
}

func Count(counter *int32) func() {
	atomic.AddInt32(counter, 1)
	return func() { atomic.AddInt32(counter, -1) }
}
