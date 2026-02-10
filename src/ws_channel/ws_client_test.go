package ws_channel

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/openportio/openport-go/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func wsURL(s *httptest.Server) string {
	return "ws" + strings.TrimPrefix(s.URL, "http")
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(mt, msg)
	}
}

func TestNewWSClient(t *testing.T) {
	client := NewWSClient()
	assert.NotNil(t, client)
	assert.Nil(t, client.wsConn)
}

func TestConnect_PrimaryServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer server.Close()

	client := NewWSClient()
	err := client.Connect(wsURL(server), "ws://invalid-fallback:9999", "")
	require.NoError(t, err)
	assert.NotNil(t, client.wsConn)
	_ = client.Close()
}

func TestConnect_FallbackServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer server.Close()

	client := NewWSClient()
	err := client.Connect("ws://invalid-primary:9999", wsURL(server), "")
	require.NoError(t, err)
	assert.NotNil(t, client.wsConn)
	_ = client.Close()
}

func TestConnect_BothFail(t *testing.T) {
	client := NewWSClient()
	err := client.Connect("ws://invalid-primary:9999", "ws://invalid-fallback:9999", "")
	assert.Error(t, err)
}

func TestConnect_WithProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer server.Close()

	// Use a real HTTP proxy (the server itself won't proxy, but this tests the dialer setup).
	// With a bad proxy the connection should fail, proving the proxy config is used.
	client := NewWSClient()
	err := client.Connect(wsURL(server), wsURL(server), "http://127.0.0.1:1")
	assert.Error(t, err)
}

func TestConnect_WithInvalidProxy(t *testing.T) {
	client := NewWSClient()
	err := client.Connect("ws://localhost:9999", "ws://localhost:9999", "://bad-proxy")
	assert.Error(t, err)
}

func TestClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer server.Close()

	client := NewWSClient()
	err := client.Connect(wsURL(server), "", "")
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestInitForward(t *testing.T) {
	received := make(chan []byte, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		received <- msg
	}))
	defer server.Close()

	client := NewWSClient()
	err := client.Connect(wsURL(server), "", "")
	require.NoError(t, err)
	defer client.Close()

	err = client.InitForward("test-token-123", 8080)
	require.NoError(t, err)

	select {
	case msg := <-received:
		var req TunnelRequest
		err := json.Unmarshal(msg, &req)
		require.NoError(t, err)
		assert.Equal(t, uint32(8080), req.Port)
		assert.Equal(t, "test-token-123", req.Token)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for message")
	}
}

func TestInitForward_WriteError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer server.Close()

	client := NewWSClient()
	err := client.Connect(wsURL(server), "", "")
	require.NoError(t, err)

	// Close the connection first so writing fails
	_ = client.Close()

	err = client.InitForward("token", 8080)
	assert.Error(t, err)
}

func TestForwardPort_NewChannelAndData(t *testing.T) {
	// Start a local TCP server that echoes data back
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer localListener.Close()
	localPort := localListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := localListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Create a WebSocket server that simulates sending a new channel + data + close
	serverDone := make(chan struct{})
	responseReceived := make(chan []byte, 10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Send a "new channel" message: 4 bytes IP + 2 bytes port + 1 byte ChOpNew
		ip := [4]byte{127, 0, 0, 1}
		port := uint16(12345)
		portBytes := []byte{byte(port), byte(port >> 8)} // little-endian
		header := append(ip[:], portBytes...)

		newMsg := append(header, byte(ChOpNew))
		err = conn.WriteMessage(websocket.BinaryMessage, newMsg)
		if err != nil {
			return
		}

		// Give ForwardPort time to establish the local connection
		time.Sleep(100 * time.Millisecond)

		// Send data on the channel
		payload := []byte("hello from server")
		dataMsg := append(append(header, byte(ChOpCont)), payload...)
		err = conn.WriteMessage(websocket.BinaryMessage, dataMsg)
		if err != nil {
			return
		}

		// Read the response (echoed data from local server, forwarded back)
		_, resp, err := conn.ReadMessage()
		if err != nil {
			return
		}
		responseReceived <- resp

		// Send close
		closeMsg := append(header, byte(ChOpClose))
		_ = conn.WriteMessage(websocket.BinaryMessage, closeMsg)

		// Allow time for the close to be processed
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}))
	defer server.Close()

	client := NewWSClient()
	err = client.Connect(wsURL(server), "", "")
	require.NoError(t, err)

	go client.ForwardPort(localPort)

	select {
	case resp := <-responseReceived:
		// The response is a channel message: header (6 bytes) + ChOp (1 byte) + payload
		assert.True(t, len(resp) > 7, "response should contain header + data")
		// Extract the payload (skip 6-byte header + 1 byte chop)
		respPayload := resp[7:]
		assert.Equal(t, "hello from server", string(respPayload))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for echoed response")
	}

	<-serverDone
}

func TestForwardPort_ConnectionToLocalServerFails(t *testing.T) {
	// Use a port that nothing is listening on
	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	closedListener.Close() // close so nothing listens

	closeReceived := make(chan bool, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Send a "new channel" message
		ip := [4]byte{127, 0, 0, 1}
		port := uint16(12345)
		portBytes := []byte{byte(port), byte(port >> 8)}
		header := append(ip[:], portBytes...)
		newMsg := append(header, byte(ChOpNew))
		_ = conn.WriteMessage(websocket.BinaryMessage, newMsg)

		// Read the close message from client (since it can't connect locally)
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if len(msg) >= 7 && ChOp(msg[6]) == ChOpClose {
			closeReceived <- true
		}

		// Close the websocket to end ForwardPort
		time.Sleep(50 * time.Millisecond)
		conn.Close()
	}))
	defer server.Close()

	client := NewWSClient()
	err = client.Connect(wsURL(server), "", "")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		client.ForwardPort(closedPort)
		close(done)
	}()

	select {
	case <-closeReceived:
		// Client sent a close for the channel it couldn't connect locally
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for close message")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ForwardPort did not return")
	}
}

func TestStartReverseTunnel(t *testing.T) {
	// Start a local TCP server
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer localListener.Close()
	localPort := localListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := localListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	tunnelRequestReceived := make(chan TunnelRequest, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the tunnel request (InitForward)
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var req TunnelRequest
		if json.Unmarshal(msg, &req) == nil {
			tunnelRequestReceived <- req
		}

		// Close the connection to end ForwardPort
		time.Sleep(50 * time.Millisecond)
		conn.Close()
	}))
	defer server.Close()

	client := NewWSClient()
	err = client.Connect(wsURL(server), "", "")
	require.NoError(t, err)

	session := database.Session{
		SessionToken: "my-token",
		RemotePort:   9090,
		LocalPort:    localPort,
	}

	callbackCalled := false
	err = client.StartReverseTunnel(session, func() {
		callbackCalled = true
	})
	require.NoError(t, err)
	assert.True(t, callbackCalled)

	select {
	case req := <-tunnelRequestReceived:
		assert.Equal(t, uint32(9090), req.Port)
		assert.Equal(t, "my-token", req.Token)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for tunnel request")
	}
}

func TestStartReverseTunnel_InitForwardError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer server.Close()

	client := NewWSClient()
	err := client.Connect(wsURL(server), "", "")
	require.NoError(t, err)

	// Close the connection so InitForward fails
	_ = client.Close()

	session := database.Session{
		SessionToken: "token",
		RemotePort:   9090,
		LocalPort:    8080,
	}

	callbackCalled := false
	err = client.StartReverseTunnel(session, func() {
		callbackCalled = true
	})
	assert.Error(t, err)
	assert.False(t, callbackCalled, "callback should not be called on error")
}

func TestForwardPort_ConcurrentChannels(t *testing.T) {
	const numChannels = 50

	// Start a local TCP echo server
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer localListener.Close()
	localPort := localListener.Addr().(*net.TCPAddr).Port

	// echoserver
	go func() {
		for {
			conn, err := localListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Track how many round-trips succeed
	var successCount atomic.Int64
	var wgServer sync.WaitGroup
	wgServer.Add(1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wgServer.Done()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// We need a mutex for writing since gorilla websocket doesn't
		// allow concurrent writes.
		var writeMu sync.Mutex

		// Open all channels simultaneously
		var wg sync.WaitGroup
		for i := 0; i < numChannels; i++ {
			wg.Add(1)
			go func(channelIdx int) {
				defer wg.Done()

				ip := [4]byte{10, 0, byte(channelIdx >> 8), byte(channelIdx)}
				portVal := uint16(20000 + channelIdx)
				portBytes := make([]byte, 2)
				binary.LittleEndian.PutUint16(portBytes, portVal)
				header := append(ip[:], portBytes...)

				// Send ChOpNew
				newMsg := append(header, byte(ChOpNew))
				writeMu.Lock()
				err := conn.WriteMessage(websocket.BinaryMessage, newMsg)
				writeMu.Unlock()
				if err != nil {
					return
				}

				// Give ForwardPort time to dial the local server
				time.Sleep(150 * time.Millisecond)

				// Send data
				payload := []byte(fmt.Sprintf("ping-%d", channelIdx))
				dataMsg := append(append(header, byte(ChOpCont)), payload...)
				writeMu.Lock()
				err = conn.WriteMessage(websocket.BinaryMessage, dataMsg)
				writeMu.Unlock()
				if err != nil {
					return
				}

				successCount.Add(1)
			}(i)
		}

		wg.Wait()

		// Drain echoed responses from the client before closing
		done := make(chan struct{})
		go func() {
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					close(done)
					return
				}
			}
		}()

		// Send close for all channels
		for i := 0; i < numChannels; i++ {
			ip := [4]byte{10, 0, byte(i >> 8), byte(i)}
			portVal := uint16(20000 + i)
			portBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(portBytes, portVal)
			header := append(ip[:], portBytes...)
			closeMsg := append(header, byte(ChOpClose))
			writeMu.Lock()
			_ = conn.WriteMessage(websocket.BinaryMessage, closeMsg)
			writeMu.Unlock()
		}

		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	client := NewWSClient()
	err = client.Connect(wsURL(server), "", "")
	require.NoError(t, err)

	forwardDone := make(chan struct{})
	go func() {
		client.ForwardPort(localPort)
		close(forwardDone)
	}()

	wgServer.Wait()

	select {
	case <-forwardDone:
	case <-time.After(10 * time.Second):
		t.Fatal("ForwardPort did not return after server closed")
	}

	assert.Equal(t, int64(numChannels), successCount.Load(),
		"all %d channels should have been sent data", numChannels)
}
