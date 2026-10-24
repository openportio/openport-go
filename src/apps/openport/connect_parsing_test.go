package main

import (
	"testing"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestParseConnectTarget(t *testing.T) {
	device, port, err := parseConnectTarget([]string{"device-a", "22"})
	assert.NoError(t, err)
	assert.Equal(t, "device-a", device)
	assert.Equal(t, 22, port)

	device, port, err = parseConnectTarget([]string{"device-a:3306"})
	assert.NoError(t, err)
	assert.Equal(t, "device-a", device)
	assert.Equal(t, 3306, port)

	_, _, err = parseConnectTarget([]string{"device-a"})
	assert.Error(t, err)

	_, _, err = parseConnectTarget([]string{"device-a", "not-a-port"})
	assert.Error(t, err)

	_, _, err = parseConnectTarget([]string{"device-a", "99999"})
	assert.Error(t, err)

	_, _, err = parseConnectTarget([]string{"device-a", "22", "extra"})
	assert.Error(t, err)

	_, _, err = parseConnectTarget([]string{":22"})
	assert.Error(t, err)
}

func sshTestFlagSet() *flag.FlagSet {
	set := flag.NewFlagSet("connect", flag.ContinueOnError)
	set.String("server", "", "")
	set.BoolP("verbose", "v", false, "")
	return set
}

func TestSplitSSHArgs(t *testing.T) {
	opFlags, sshOptions, destination, remoteCommand, devicePort := splitSSHArgs([]string{"root@device-a"}, sshTestFlagSet())
	assert.Empty(t, opFlags)
	assert.Empty(t, sshOptions)
	assert.Equal(t, "root@device-a", destination)
	assert.Empty(t, remoteCommand)
	assert.Equal(t, "", devicePort)

	// An ssh option with a value must not be mistaken for the destination.
	opFlags, sshOptions, destination, remoteCommand, devicePort = splitSSHArgs(
		[]string{"-i", "key.pem", "root@device-a", "uptime"}, sshTestFlagSet())
	assert.Empty(t, opFlags)
	assert.Equal(t, []string{"-i", "key.pem"}, sshOptions)
	assert.Equal(t, "root@device-a", destination)
	assert.Equal(t, []string{"uptime"}, remoteCommand)

	// Openport's own long flags consume their value; ssh's single-dash
	// flags stay with ssh; everything after the destination is the remote
	// command, even flag-looking tokens.
	opFlags, sshOptions, destination, remoteCommand, devicePort = splitSSHArgs(
		[]string{"--server", "https://test.openport.io", "--verbose", "-A", "device-a", "ls", "-la"}, sshTestFlagSet())
	assert.Equal(t, []string{"--server", "https://test.openport.io", "--verbose"}, opFlags)
	assert.Equal(t, []string{"-A"}, sshOptions)
	assert.Equal(t, "device-a", destination)
	assert.Equal(t, []string{"ls", "-la"}, remoteCommand)
	assert.Equal(t, "", devicePort)

	// A combined option+value token ("-p2222") takes no extra token.
	_, sshOptions, destination, _, devicePort = splitSSHArgs([]string{"-i", "key.pem", "-p2222", "device-a"}, sshTestFlagSet())
	assert.Equal(t, []string{"-i", "key.pem"}, sshOptions)
	assert.Equal(t, "device-a", destination)
	assert.Equal(t, "2222", devicePort)

	// "-p" is the device's ssh port: ssh itself always dials the tunnel
	// (and would ignore a second "-p" anyway).
	_, sshOptions, destination, _, devicePort = splitSSHArgs([]string{"-p", "2222", "device-a"}, sshTestFlagSet())
	assert.Empty(t, sshOptions)
	assert.Equal(t, "device-a", destination)
	assert.Equal(t, "2222", devicePort)

	// Grouped options, getopt style: a value option ends the group and
	// takes the next token when nothing is attached to it.
	_, sshOptions, destination, remoteCommand, devicePort = splitSSHArgs([]string{"-Ai", "key.pem", "device-a", "uptime"}, sshTestFlagSet())
	assert.Equal(t, []string{"-Ai", "key.pem"}, sshOptions)
	assert.Equal(t, "device-a", destination)
	assert.Equal(t, []string{"uptime"}, remoteCommand)
	assert.Equal(t, "", devicePort)

	_, sshOptions, destination, _, devicePort = splitSSHArgs([]string{"-vtp", "2222", "-Aikey.pem", "device-a"}, sshTestFlagSet())
	assert.Equal(t, []string{"-vt", "-Ai", "key.pem"}, sshOptions)
	assert.Equal(t, "device-a", destination)
	assert.Equal(t, "2222", devicePort)

	_, sshOptions, _, _, devicePort = splitSSHArgs([]string{"-vvp2222", "device-a"}, sshTestFlagSet())
	assert.Equal(t, []string{"-vv"}, sshOptions)
	assert.Equal(t, "2222", devicePort)

	// No destination at all.
	_, _, destination, _, _ = splitSSHArgs([]string{"-v"}, sshTestFlagSet())
	assert.Equal(t, "", destination)
}

func TestSplitUserDevice(t *testing.T) {
	sshUser, device := splitUserDevice("root@device-a")
	assert.Equal(t, "root", sshUser)
	assert.Equal(t, "device-a", device)

	sshUser, device = splitUserDevice("device-a")
	assert.Equal(t, "", sshUser)
	assert.Equal(t, "device-a", device)

	// Like ssh: the part before the LAST @ is the user.
	sshUser, device = splitUserDevice("user@example.com@device-a")
	assert.Equal(t, "user@example.com", sshUser)
	assert.Equal(t, "device-a", device)
}

func TestBuildSSHCommand(t *testing.T) {
	command := buildSSHCommand("root", "device-a", 22, nil, nil)
	assert.Equal(t, []string{
		"ssh", "-p", "$port", "-o", "HostKeyAlias=openport-device-a", "-l", "root", "127.0.0.1",
	}, command)

	command = buildSSHCommand("", "device-a", 22, []string{"-i", "key.pem"}, []string{"uptime"})
	assert.Equal(t, []string{
		"ssh", "-p", "$port", "-o", "HostKeyAlias=openport-device-a", "-i", "key.pem", "127.0.0.1", "uptime",
	}, command)

	// Another ssh server on the device has its own host key.
	command = buildSSHCommand("", "device-a", 2222, nil, nil)
	assert.Equal(t, []string{
		"ssh", "-p", "$port", "-o", "HostKeyAlias=openport-device-a:2222", "127.0.0.1",
	}, command)
}
