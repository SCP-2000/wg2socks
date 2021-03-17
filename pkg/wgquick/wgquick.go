package wgquick

import (
	"encoding/base64"
	"github.com/SCP-2000/wg2socks/pkg/wgnet"
	"gopkg.in/ini.v1"
	"net"
)

func ParseWGQuick(raw []byte) (*wgnet.Config, error) {
	data, err := ini.ShadowLoad(raw)
	if err != nil {
		return nil, err
	}

	var config wgnet.Config
	itf := data.Section("Interface")

	sk, err := base64.StdEncoding.DecodeString(itf.Key("PrivateKey").String())
	if err != nil {
		return nil, err
	}
	copy(config.Interface.PrivateKey[:], sk)
	config.Interface.ListenPort = uint16(itf.Key("ListenPort").MustInt(0))
	config.Interface.FirewallMark = uint32(itf.Key("FwMark").MustInt(0))
	config.Interface.MTU = uint16(itf.Key("MTU").MustInt(1280))
	addrs := itf.Key("Address").StringsWithShadows(",")
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, err
		}
		config.Interface.Address = append(config.Interface.Address, ip)
	}
	dnses := itf.Key("DNS").StringsWithShadows(",")
	for _, dns := range dnses {
		ip := net.ParseIP(dns)
		if ip != nil {
			config.Interface.DNS = append(config.Interface.DNS, ip)
		}
	}

	var p wgnet.Peer
	peer := data.Section("Peer")
	pk, err := base64.StdEncoding.DecodeString(peer.Key("PublicKey").String())
	if err != nil {
		return nil, err
	}
	copy(p.PublicKey[:], pk)
	psk, err := base64.StdEncoding.DecodeString(peer.Key("PresharedKey").String())
	if err != nil {
		return nil, err
	}
	copy(p.PresharedKey[:], psk)
	cidrs := peer.Key("AllowedIPs").StringsWithShadows(",")
	for _, cidr := range cidrs {
		_, anet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		p.AllowedIPs = append(p.AllowedIPs, *anet)
	}
	p.Endpoint, _ = net.ResolveUDPAddr("udp", peer.Key("Endpoint").String())
	p.PersistentKeepalive = uint16(peer.Key("PersistentKeepalive").MustInt(0))
	config.Peers = append(config.Peers, p)
	return &config, nil
}
