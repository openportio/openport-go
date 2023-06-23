package ws_channel

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/openportio/openport-go/database"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"strconv"
	"strings"
)

type WSClient struct {
	wsConn *net.Conn
}

func (client *WSClient) Connect(server string) error {
	wsConn, _, _, err := ws.DefaultDialer.Dial(context.Background(), server+"/ws")
	client.wsConn = &wsConn
	if err != nil {
		return err
	} else {
		fmt.Println("Connected to server")
		return nil
	}
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

		log.Info("Channel Key: ", channel.GetKey())
		if chop == ChOpNew {
			log.Info("Got new channel from server!")
			conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(localPort))
			if err != nil {
				if err != io.EOF {
					log.Error("Could not connect to local server: ", err)
				}
				_ = channel.Close()
				continue

			}
			log.Info("Dialed")
			channel.NetConn = &conn
			channels[channel.GetKey()] = channel

			go func() {
				// Write responses to websocket conn
				for {
					byts := make([]byte, 4096) // todo buffer
					len, err := (*channel.NetConn).Read(byts)
					log.Debugf("Got message from conn: %d", len)

					if err != nil {
						if err != io.EOF {
							log.Error("Error reading from local server:", err)
						} else {
							log.Info("Got close from local server")
							_ = (*channel.NetConn).Close()
							_ = channel.Close()
						}
						return
					}
					err = channel.Send(byts[:len])
					if err != nil {
						if err != io.EOF {
							log.Error("Could not send to the websocket: ", err)
						} else {
							log.Info("Got close from remote server")
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
					log.Info("Got DATA from server!")
					channel, ok := channels[channel.GetKey()]
					if !ok {
						log.Errorf("Trying to get unknown channel: %s", channel.GetKey())
					} else {
						_, err := (*channel.NetConn).Write(msg)
						if err != nil {
							if err != io.EOF {
								log.Error("could not write to local server: ", err)
							} else {
								log.Info("Got close from remote server")
								_ = channel.Close()
								_ = (*channel.NetConn).Close()
							}
						}

					}
				} else if chop == ChOpClose {
					log.Info("Got close from server!")
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

	err = wsutil.WriteClientText(*client.wsConn, jsonRequest)
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
