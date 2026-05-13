package utils

import (
	"encoding/binary"
	"fmt"
	"io"
)

// UDP datagrams are framed over SSH stream channels using a simple length-prefix protocol:
//   [2 bytes: payload length (big-endian uint16)] [N bytes: payload]
// Max payload size is 65535 bytes which covers the maximum UDP datagram size.

const MaxUDPPayload = 65535

// WriteFrame writes a length-prefixed datagram to the writer.
func WriteFrame(w io.Writer, data []byte) error {
	if len(data) > MaxUDPPayload {
		return fmt.Errorf("datagram too large: %d > %d", len(data), MaxUDPPayload)
	}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(data)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadFrame reads a length-prefixed datagram from the reader.
// Returns the payload or an error (including io.EOF when the stream ends).
func ReadFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header)
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
