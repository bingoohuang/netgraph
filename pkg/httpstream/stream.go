package httpstream

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type streamKey struct {
	net, tcp gopacket.Flow
}

func (k *streamKey) String() string {
	return fmt.Sprintf("{%v:%v} -> {%v:%v}", k.net.Src(), k.tcp.Src(), k.net.Dst(), k.tcp.Dst())
}

type httpStream struct {
	reader *Reader
	bytes  uint64
	key    streamKey
	bad    bool
}

func newHTTPStream(key streamKey) *httpStream {
	return &httpStream{reader: NewReader(), key: key}
}

// Reassembled is called by tcpassembly.
func (s *httpStream) Reassembled(rs []tcpassembly.Reassembly) {
	if s.bad {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for _, r := range rs {
		if r.Skip != 0 {
			s.bad = true
			return
		}

		if len(r.Bytes) == 0 {
			continue
		}

		s.bytes += uint64(len(r.Bytes))
		ticker.Reset(time.Second)

		select {
		case <-s.reader.stopCh:
			s.bad = true
			return
		case s.reader.src <- NewDataBlock(r.Bytes, r.Seen):
		case <-ticker.C:
			// Sometimes pcap only captured HTTP response with no request!
			// Let's wait few seconds to avoid dead lock.
			s.bad = true
			return
		}
	}
}

// ReassemblyComplete is called by tcpassembly.
func (s *httpStream) ReassemblyComplete() {
	close(s.reader.src)
}

var (
	httpRequestFirstLine  = regexp.MustCompile(`^([A-Z]+) (.+) (HTTP/.+)\r\n`)
	httpResponseFirstLine = regexp.MustCompile(`^(HTTP/.+) (\d{3}) (.+)\r\n`)
)

type Direction int

const (
	DirectionUnknown Direction = iota
	DirectionRequest
	DirectionResponse
)

func (s *httpStream) parseFirstLine(initDir Direction) (dir Direction, p1, p2, p3 string, err error) {
	b, err := s.reader.ReadUntil([]byte("\r\n"))
	if err != nil {
		return DirectionUnknown, "", "", "", fmt.Errorf("read first line, %w", err)
	}

	line := string(b)
	switch initDir {
	case DirectionUnknown:
		if r := httpResponseFirstLine.FindStringSubmatch(line); len(r) == 4 {
			return DirectionResponse, r[1], r[2], r[3], nil
		}
		if r := httpRequestFirstLine.FindStringSubmatch(line); len(r) == 4 {
			return DirectionRequest, r[1], r[2], r[3], nil
		}
	case DirectionRequest:
		if r := httpRequestFirstLine.FindStringSubmatch(line); len(r) == 4 {
			return DirectionRequest, r[1], r[2], r[3], nil
		}
	case DirectionResponse:
		if r := httpResponseFirstLine.FindStringSubmatch(line); len(r) == 4 {
			return DirectionResponse, r[1], r[2], r[3], nil
		}
	}
	return DirectionUnknown, "", "", "", fmt.Errorf("bad HTTP first line: %s", line)
}

func (s *httpStream) parseHeader() (header http.Header, err error) {
	d, err := s.reader.ReadUntil([]byte("\r\n\r\n"))
	if err != nil {
		return nil, fmt.Errorf("read headers error: %w", err)
	}

	header = make(http.Header)
	data := string(d[:len(d)-4])
	for i, line := range strings.Split(data, "\r\n") {
		p := strings.Index(line, ":")
		if p == -1 {
			return nil, fmt.Errorf("bad http header (line %d): %s", i, data)
		}

		header.Add(line[:p], strings.Trim(line[p+1:], " "))
	}

	return header, nil
}

func (s *httpStream) parseChunked() (body []byte, err error) {
	var buf []byte
	for {
		if buf, err = s.reader.ReadUntil([]byte("\r\n")); err != nil {
			return nil, fmt.Errorf("read chuncked content, error: %w", err)
		}
		l := string(buf)
		l = strings.Trim(l[:len(l)-2], " ")
		blockSize, err := strconv.ParseInt(l, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("bad chunked block length %s, error: %w", l, err)
		}

		if blockSize > 0 {
			if buf, err = s.reader.Next(int(blockSize)); err != nil {
				return nil, fmt.Errorf("read chuncked content, error: %w", err)
			}
			body = append(body, buf...)
		}

		if buf, err = s.reader.Next(2); err != nil {
			return nil, fmt.Errorf("read chuncked content, error: %w", err)
		}
		if CRLF := string(buf); CRLF != "\r\n" {
			return nil, fmt.Errorf("bad chunked block data")
		}

		if blockSize == 0 {
			break
		}
	}

	return body, nil
}

func parseContentInfo(hs http.Header) (contentLen int, contentEncoding, contentType string, chunked bool, err error) {
	for name := range hs {
		switch value := hs.Get(name); strings.ToLower(name) {
		case "content-length":
			if contentLen, err = strconv.Atoi(value); err != nil {
				return contentLen, contentEncoding, contentType, chunked,
					fmt.Errorf("content-Length: %s, error: %w", value, err)
			}
		case "transfer-encoding":
			chunked = value == "chunked"
		case "content-encoding":
			contentEncoding = value
		case "content-type":
			contentType = value
		}
	}

	return contentLen, contentEncoding, contentType, chunked, nil
}

func (s *httpStream) parseBody(method string, header http.Header, isRequest bool) (body []byte, e error) {
	cLength, cEncoding, _, chunked, err := parseContentInfo(header)
	if err != nil {
		return nil, err
	}

	if cLength == 0 && !chunked || !isRequest && method == "HEAD" {
		return nil, nil
	}

	if chunked {
		body, err = s.parseChunked()
	} else {
		body, err = s.reader.Next(cLength)
	}
	if err != nil {
		return nil, err
	}

	switch cEncoding {
	case "gzip":
		r, _ := gzip.NewReader(bytes.NewBuffer(body))
		data, err := ioutil.ReadAll(r)
		_ = r.Close()
		return data, err
	case "deflate":
		r, _ := zlib.NewReader(bytes.NewBuffer(body))
		data, err := ioutil.ReadAll(r)
		_ = r.Close()
		return data, err
	}

	return body, nil
}
