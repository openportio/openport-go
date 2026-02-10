package ws_channel

import (
	"encoding/binary"
	"fmt"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
)

type TunnelRequest struct {
	Port  uint32
	Token string
}

type ChannelType byte

const (
	ClientChannelType ChannelType = 0x01
	ServerChannelType ChannelType = 0x02
)

type Channel struct {
	IP          [4]byte // TODO: change to netip.Addr
	Port        uint16
	WSConn      *websocket.Conn // websocket connection between the client and server
	NetConn     *net.Conn       // Connection on listener on the server side, and connection to the local server on the client side
	QuitChannel chan bool
	channelType ChannelType
	writeMu     *sync.Mutex // protects concurrent writes to WSConn
}

type ChOp byte

const (
	ChOpUnknown ChOp = 0x00
	ChOpNew     ChOp = 0x01
	ChOpCont    ChOp = 0x02
	ChOpClose   ChOp = 0x03
)

type ChannelError struct {
	Message string
}

func (e *ChannelError) Error() string {
	return e.Message
}

func (c *Channel) GetKey() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", c.IP[0], c.IP[01], c.IP[2], c.IP[3], c.Port)
}

func (c *Channel) GetHeader() []byte {
	bs := make([]byte, 2)
	binary.LittleEndian.PutUint16(bs, c.Port)
	log.Trace("ip: ", c.IP)
	log.Trace("bs: ", bs)
	return append(c.IP[:], bs...)
}

func (c *Channel) Write(newMsg []byte) error {
	log.Trace("sending a packet to the websocket ", c.GetKey(), newMsg)
	if c.writeMu != nil {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
	}
	return c.WSConn.WriteMessage(websocket.BinaryMessage, newMsg) // client message
}
func (c *Channel) Close() error {
	newMsg := c.getPayload(ChOpClose, []byte(""))
	return c.Write(newMsg)
}

func (c *Channel) Send(msg []byte) error {
	newMsg := c.getPayload(ChOpCont, msg)
	return c.Write(newMsg)
}

func (c *Channel) getPayload(chop ChOp, msg []byte) []byte {
	log.Trace("channel key: ", c.GetKey())
	log.Trace("msg header: ", c.GetHeader())
	return append(append(c.GetHeader(), byte(chop)), msg...) // TODO: not very efficient?
}

func ChannelFromServerMessage(wsConn *websocket.Conn, writeMu *sync.Mutex) (*Channel, []byte, ChOp, error) {
	_, msg, err := wsConn.ReadMessage()
	return ChannelFromMsg(err, msg, wsConn, ClientChannelType, writeMu)
}

func ChannelFromMsg(err error, msg []byte, wsConn *websocket.Conn, channelType ChannelType, writeMu *sync.Mutex) (*Channel, []byte, ChOp, error) {
	if err != nil {
		return nil, nil, ChOpUnknown, err
	}
	if len(msg) < 7 {
		return nil, nil, ChOpUnknown, &ChannelError{fmt.Sprintf("msg is too short: %d", len(msg))}
	}
	ip := [4]byte{msg[0], msg[1], msg[2], msg[3]}
	channel := &Channel{
		IP:          ip,
		Port:        binary.LittleEndian.Uint16(msg[4:6]),
		WSConn:      wsConn,
		NetConn:     nil,
		QuitChannel: make(chan bool),
		channelType: channelType,
		writeMu:     writeMu,
	}
	return channel, msg[7:], ChOp(msg[6]), nil
}
