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
	for {
		channel, msg, chop, err := ChannelFromServerMessage(client.wsConn)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Error("Could not get channel from websocket: ", err)
			}
			return
		}

		log.Trace("Channel Key: ", channel.GetKey())
		if chop == ChOpNew {
			log.Trace("Got new channel from server!")
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
				// Write responses to websocket conn
				for {
					byts := make([]byte, 4096) // todo buffer
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
		} else {
			oldChannel, ok := channels[channel.GetKey()]
			if !ok {
				log.Errorf("Trying to get unknown channel: %s", channel.GetKey())
			} else {
				channel = oldChannel
				if chop == ChOpCont {
					log.Trace("Got DATA from server!")
					channel, ok := channels[channel.GetKey()]
					if !ok {
						log.Errorf("Trying to get unknown channel: %s", channel.GetKey())
					} else {
						_, err := (*channel.NetConn).Write(msg)
						if err != nil {
							if err != io.EOF {
								log.Error("could not write to local server: ", err)
							} else {
								log.Trace("Got close from remote server")
								_ = channel.Close()
								_ = (*channel.NetConn).Close()
							}
						}

					}
				} else if chop == ChOpClose {
					log.Trace("Got close from server!")
					_ = (*channel.NetConn).Close()
				} else {
					log.Errorf("unknown Channel Operation: %#v", chop)
				}
			}
		}
	}

}

func (client *WSClient) InitForward(token string, remotePort int) error {
	tunnelRequest := TunnelRequest{
		Port:  uint32(remotePort),
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

func (client *WSClient) StartReverseTunnel(session database.Session, message string) error {

	err := client.InitForward(session.SessionToken, session.RemotePort)
	if err != nil {
		return err
	}
	session.PrintMessage(message)
	client.ForwardPort(session.LocalPort)
	return nil

}

func (client *WSClient) Close() error {
	return (*client.wsConn).Close()

}
