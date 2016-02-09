package main

import (
	"fmt"
	"net/http"
	"io/ioutil"
	"net/url"
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"net"
	"log"
	"io"
	"os/user"
)


type PortResponse struct {
	Server_ip   string `json:"server_ip"`
	//	fallback_ssh_server_ip   string
	//	fallback_ssh_server_port int
	//	session_max_bytes        int64
	//	open_port_for_ip_link    string
	//	message                 string
	//	session_end_time         float64
	//	account_id               int
	//	session_token            string
	//	session_id               int
	//	http_forward_address     string
	Server_port int `json:"server_port"`
	//	key_id                   int
	Error       string`json:"error"`
	//	fatal_error              bool
}

func main() {
	usr, _ := user.Current()
	file := usr.HomeDir + "/.openport/id_rsa"

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	public_key, err := ioutil.ReadFile(file + ".pub")

	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(public_key))

	post_url := "https://openport.io/api/v1/request-port"
	//post_url = "http://localhost:8000/internal/request-port"
	resp, err := http.PostForm(post_url,
		url.Values{"public_key": {string(public_key)}, "id": {"123"}})
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("http error")
		log.Fatal(err)
	}
	fmt.Println(string(body))

	var jsonData = []byte(body)

	response := PortResponse{}
	var dat map[string]interface{}

	json_err := json.Unmarshal(jsonData, &response)
	if json_err != nil {
		fmt.Println("json error")
		log.Fatal(json_err)
	}

	config := &ssh.ClientConfig{
		User: "open",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", response.Server_ip, 22), config)
	if err != nil {
		panic("Failed to dial: " + err.Error())
	}

	log.Println("connected")

	s := fmt.Sprintf("localhost:%d", response.Server_port)

	addr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		panic("Could not get address: " + err.Error())
	}

	listener, err := conn.ListenTCP(addr)

	if err != nil {
		log.Fatal(err.Error())
	}
	log.Println("forwarding")

	defer listener.Close()
	for {
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func(c net.Conn) {
			log.Println("new request")
			conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", 8000))
			if err != nil {
				log.Fatal(err)
			}

			go func() {
				defer c.Close()
				defer conn.Close()
				io.Copy(c, conn)
			}()
			go func() {
				defer c.Close()
				defer conn.Close()
				io.Copy(conn, c)
			}()

		}(conn)
	}
}

