package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"gopkg.in/yaml.v2"
	"net"
	"strings"
)

type IPNet net.IPNet

func (i *IPNet) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	_, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return err
	}
	*i = IPNet(*ipNet)
	return nil
}

type EndpointAddr net.UDPAddr

func (e *EndpointAddr) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", raw)
	if err != nil {
		return err
	}
	*e = EndpointAddr(*addr)
	return nil
}

type Key []byte

func (k *Key) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	*k = data
	return nil
}

type Interface struct {
	PrivateKey Key      `yaml:"private_key"`
	ListenPort uint16   `yaml:"listen_port"`
	FwMark     uint32   `yaml:"fw_mark"`
	Address    []IPNet  `yaml:"address"`
	DNS        []net.IP `yaml:"dns"`
	MTU        uint16   `yaml:"mtu"`
}

type Peer struct {
	PublicKey           Key          `yaml:"public_key"`
	PresharedKey        Key          `yaml:"preshared_key"`
	AllowedIPs          []IPNet      `yaml:"allowed_ips"`
	Endpoint            EndpointAddr `yaml:"endpoint"`
	PersistentKeepalive uint16       `yaml:"persistent_keepalive"`
}

type Config struct {
	Listen    EndpointAddr `yaml:"listen"`
	Interface Interface    `yaml:"interface"`
	Peer      []Peer       `yaml:"peer"`
}

func ConfigFromYAML(data []byte) (*Config, error) {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *Config) ToUAPI() (string, error) {
	var output strings.Builder
	output.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(c.Interface.PrivateKey)))
	if len(c.Peer) > 0 {
		output.WriteString("replace_peers=true\n")
	}
	for _, peer := range c.Peer {
		output.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(peer.PublicKey)))
		if len(peer.PresharedKey) > 0 {
			output.WriteString(fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(peer.PresharedKey)))
		}
		if len(peer.Endpoint.IP) > 0 {
			ep := net.UDPAddr(peer.Endpoint)
			output.WriteString(fmt.Sprintf("endpoint=%s\n", (&ep).String()))
		}
		if peer.PersistentKeepalive > 0 {
			output.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
		if len(peer.AllowedIPs) > 0 {
			output.WriteString("replace_allowed_ips=true\n")
			for _, address := range peer.AllowedIPs {
				addr := net.IPNet(address)
				output.WriteString(fmt.Sprintf("allowed_ip=%s\n", (&addr).String()))
			}
		}
	}
	return output.String(), nil
}
