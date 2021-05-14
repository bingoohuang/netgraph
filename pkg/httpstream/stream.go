package httpstream

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"
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

	for _, r := range rs {
		if r.Skip != 0 {
			s.bad = true
			return
		}

		if len(r.Bytes) == 0 {
			continue
		}

		s.bytes += uint64(len(r.Bytes))
		ticker := time.Tick(time.Second)

		select {
		case <-s.reader.stopCh:
			s.bad = true
			return
		case s.reader.src <- NewDataBlock(r.Bytes, r.Seen):
		case <-ticker:
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

var httpRequestFirstLine = regexp.MustCompile(`([A-Z]+) (.+) (HTTP/.+)\r\n`)

func (s *httpStream) parseRequestLine() (method, uri, version string, err error) {
	b, err := s.reader.ReadUntil([]byte("\r\n"))
	if err != nil {
		return "", "", "", fmt.Errorf("read request line, %w", err)
	}

	r := httpRequestFirstLine.FindStringSubmatch(string(b))
	if len(r) != 4 {
		return "", "", "", fmt.Errorf("bad HTTP Request: %s", b)
	}

	return r[1], r[2], r[3], nil
}

var httpResponseFirstLine = regexp.MustCompile(`(HTTP/.+) (\d{3}) (.+)\r\n`)

func (s *httpStream) parseResponseLine() (version string, code int, reason string, err error) {
	b, err := s.reader.ReadUntil([]byte("\r\n"))
	if err != nil {
		return "", 0, "", fmt.Errorf("read response line, %w", err)
	}

	r := httpResponseFirstLine.FindStringSubmatch(string(b))
	if len(r) != 4 {
		return "", 0, "", fmt.Errorf("bad HTTP Response: %s", b)
	}

	code, err = strconv.Atoi(r[2])
	if err != nil {
		return "", 0, "", fmt.Errorf("bad HTTP Response: %s, %w", b, err)
	}
	return r[1], code, r[3], nil
}

func (s *httpStream) parseHeaders() (headers []Header, err error) {
	d, err := s.reader.ReadUntil([]byte("\r\n\r\n"))
	if err != nil {
		return nil, fmt.Errorf("read headers error: %w", err)
	}

	data := string(d[:len(d)-4])
	for i, line := range strings.Split(data, "\r\n") {
		p := strings.Index(line, ":")
		if p == -1 {
			return nil, fmt.Errorf("bad http header (line %d): %s", i, data)
		}
		headers = append(headers, Header{
			Name:  line[:p],
			Value: strings.Trim(line[p+1:], " "),
		})
	}

	return headers, nil
}

func (s *httpStream) parseChunked() (body []byte, err error) {
	for {
		buf, err := s.reader.ReadUntil([]byte("\r\n"))
		if err != nil {
			return nil, fmt.Errorf("read chuncked content, error: %w", err)
		}
		l := string(buf)
		l = strings.Trim(l[:len(l)-2], " ")
		blockSize, err := strconv.ParseInt(l, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("bad chunked block length %s, error: %w", l, err)
		}

		buf, err = s.reader.Next(int(blockSize))
		body = append(body, buf...)
		if err != nil {
			return nil, fmt.Errorf("read chuncked content, error: %w", err)
		}
		buf, err = s.reader.Next(2)
		if err != nil {
			return nil, fmt.Errorf("read chuncked content, error: %w", err)
		}
		CRLF := string(buf)
		if CRLF != "\r\n" {
			return nil, fmt.Errorf("bad chunked block data")
		}

		if blockSize == 0 {
			break
		}
	}
	return body, nil
}

func parseContentInfo(hs []Header) (contentLen int, contentEncoding, contentType string, chunked bool, err error) {
	for _, h := range hs {
		switch strings.ToLower(h.Name) {
		case "content-length":
			if contentLen, err = strconv.Atoi(h.Value); err != nil {
				return 0, "", "", false,
					fmt.Errorf("content-Length: %s, error: %w", h.Value, err)
			}
		case "transfer-encoding":
			chunked = h.Value == "chunked"
		case "content-encoding":
			contentEncoding = h.Value
		case "content-type":
			contentType = h.Value
		}
	}
	return
}

func (s *httpStream) parseBody(method string, headers []Header, isRequest bool) (body []byte, e error) {
	cLength, cEncoding, _, chunked, err := parseContentInfo(headers)
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
		defer r.Close()
		return data, err
	case "deflate":
		r, _ := zlib.NewReader(bytes.NewBuffer(body))
		data, err := ioutil.ReadAll(r)
		defer r.Close()
		return data, err
	}

	return body, nil
}
