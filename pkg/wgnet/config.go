package wgnet

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

type Key [32]byte

type Config struct {
	Interface Interface
	Peers     []Peer
}

type Interface struct {
	PrivateKey   Key
	ListenPort   uint16
	FirewallMark uint32
	Address      []net.IP
	DNS          []net.IP
	MTU          uint16
}

type Peer struct {
	PublicKey           Key
	PresharedKey        Key
	AllowedIPs          []net.IPNet
	Endpoint            *net.UDPAddr
	PersistentKeepalive uint16
}

func (c *Config) ToUAPI() (string, error) {
	var output strings.Builder
	output.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(c.Interface.PrivateKey[:])))
	if len(c.Peers) > 0 {
		output.WriteString("replace_peers=true\n")
	}
	for _, peer := range c.Peers {
		output.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(peer.PublicKey[:])))
		output.WriteString(fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(peer.PresharedKey[:])))
		if peer.Endpoint != nil {
			output.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint.String()))
		}
		if peer.PersistentKeepalive > 0 {
			output.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
		if len(peer.AllowedIPs) > 0 {
			output.WriteString("replace_allowed_ips=true\n")
		}
		for _, address := range peer.AllowedIPs {
			output.WriteString(fmt.Sprintf("allowed_ip=%s\n", address.String()))
		}
	}
	return output.String(), nil
}
