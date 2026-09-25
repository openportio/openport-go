package ws_channel

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/openportio/openport-go/database"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

type WSClient struct {
	wsConn *websocket.Conn
}

func (client *WSClient) Connect(primaryServer string, fallbackServer string, proxyStr string) error {
	dialer := websocket.DefaultDialer
	if proxyStr != "" {
		dialer = &websocket.Dialer{
			Proxy: func(*http.Request) (*url.URL, error) {
				proxyUrl, err := url.Parse(proxyStr)
				if err != nil {
					return nil, err
				}
				return proxyUrl, nil
			},
		}
	}

	wsConn, _, err := dialer.Dial(primaryServer, nil)
	if err != nil {
		log.Debug("Could not connect to primary server: ", err)
		log.Debug("Trying fallback server: ", fallbackServer)
		wsConn, _, err = dialer.Dial(fallbackServer, nil)
		if err != nil {
			return err
		}
	}
	client.wsConn = wsConn
	log.Debug("Connected to server")
	return nil
}

func (client *WSClient) ForwardPort(localPort int) {

	// read connections from server
	channels := make(map[string]*Channel)
	udpChannels := make(map[string]*net.UDPConn) // UDP flows: key -> local UDP conn
	writeMu := &sync.Mutex{}
	for {
		channel, msg, chop, err := ChannelFromServerMessage(client.wsConn, writeMu)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Error("Could not get channel from websocket: ", err)
			}
			return
		}

		log.Trace("Channel Key: ", channel.GetKey())
		switch chop {
		case ChOpNew:
			log.Trace("Got new TCP channel from server!")
			conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(localPort))
			if err != nil {
				if err != io.EOF {
					log.Error("Could not connect to local server: ", err)
				}
				_ = channel.Close()
				continue
			}
			log.Trace("Dialed")
			channel.NetConn = &conn
			channels[channel.GetKey()] = channel

			go func() {
				for {
					byts := make([]byte, 4096)
					length, err := (*channel.NetConn).Read(byts)
					log.Tracef("Got message from conn: %d", length)
					if err != nil {
						if err != io.EOF {
							log.Error("Error reading from local server:", err)
						} else {
							log.Trace("Got close from local server")
							_ = (*channel.NetConn).Close()
							_ = channel.Close()
						}
						return
					}
					err = channel.Send(byts[:length])
					if err != nil {
						if err != io.EOF {
							log.Error("Could not send to the websocket: ", err)
						} else {
							log.Trace("Got close from remote server")
							_ = (*channel.NetConn).Close()
						}
						return
					}
				}
			}()

		case ChOpCont:
			oldChannel, ok := channels[channel.GetKey()]
			if !ok {
				log.Errorf("Trying to get unknown TCP channel: %s", channel.GetKey())
			} else {
				_, err := (*oldChannel.NetConn).Write(msg)
				if err != nil {
					if err != io.EOF {
						log.Error("could not write to local server: ", err)
					} else {
						log.Trace("Got close from remote server")
						_ = oldChannel.Close()
						_ = (*oldChannel.NetConn).Close()
					}
				}
			}

		case ChOpClose:
			oldChannel, ok := channels[channel.GetKey()]
			if ok {
				_ = (*oldChannel.NetConn).Close()
				delete(channels, channel.GetKey())
			}

		case ChOpUdpNew:
			log.Trace("Got new UDP channel from server!")
			localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+strconv.Itoa(localPort))
			if err != nil {
				log.Error("Could not resolve local UDP addr: ", err)
				_ = channel.CloseUdp()
				continue
			}
			localConn, err := net.DialUDP("udp", nil, localAddr)
			if err != nil {
				log.Error("Could not dial local UDP: ", err)
				_ = channel.CloseUdp()
				continue
			}
			udpChannels[channel.GetKey()] = localConn

			// Read responses from local UDP service and send back
			go func(ch *Channel, conn *net.UDPConn) {
				buf := make([]byte, 65535)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						log.Debugf("UDP read from local ended: %s", err)
						return
					}
					err = ch.SendUdp(buf[:n])
					if err != nil {
						log.Debugf("UDP send to websocket failed: %s", err)
						return
					}
				}
			}(channel, localConn)

		case ChOpUdpCont:
			localConn, ok := udpChannels[channel.GetKey()]
			if !ok {
				log.Errorf("Trying to get unknown UDP channel: %s", channel.GetKey())
			} else {
				_, err := localConn.Write(msg)
				if err != nil {
					log.Error("Could not write to local UDP: ", err)
				}
			}

		case ChOpUdpClose:
			localConn, ok := udpChannels[channel.GetKey()]
			if ok {
				_ = localConn.Close()
				delete(udpChannels, channel.GetKey())
			}

		default:
			log.Errorf("unknown Channel Operation: %#v", chop)
		}
	}

}

func (client *WSClient) InitForward(token string, remotePort int) error {
	tunnelRequest := TunnelRequest{
		Port:  uint32(remotePort), // #nosec G115 -- a TCP port, 0-65535
		Token: token,
	}

	jsonRequest, err := json.Marshal(tunnelRequest)
	if err != nil {
		log.Error("Could not marshal tunnel request: ", err)
		return err
	}

	err = client.wsConn.WriteMessage(websocket.TextMessage, jsonRequest)
	if err != nil {
		log.Error("Could not write tunnel request: ", err)
		return err
	}
	return nil
}

func NewWSClient() *WSClient {

	return &WSClient{}
}

func (client *WSClient) StartReverseTunnel(session database.Session, successCallback func()) error {

	err := client.InitForward(session.SessionToken, session.RemotePort)
	if err != nil {
		return err
	}
	successCallback()
	localPort := session.LocalPort
	if session.TlsProxyPort != 0 {
		localPort = session.TlsProxyPort
	}
	client.ForwardPort(localPort)
	return nil

}

func (client *WSClient) Close() error {
	return (*client.wsConn).Close()

}
