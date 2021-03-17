package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/armon/go-socks5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"log"
	"net"
)

func main() {
	var localIPs, dnsIPs IPSlice
	var mtu int
	var privateKey, publicKey, endpoint, listen string

	flag.Var(&localIPs, "ip", "list of local ip address")
	flag.Var(&dnsIPs, "dns", "list of dns ip address")
	flag.IntVar(&mtu, "mtu", 1280, "interface mtu")
	flag.StringVar(&privateKey, "key", "", "wireguard private key")
	flag.StringVar(&publicKey, "pub", "", "wireguard public key of peer")
	flag.StringVar(&endpoint, "endpoint", "", "wireguard endpoint of peer")
	flag.StringVar(&listen, "listen", "", "listen address of socks5 server")
	flag.Parse()

	tun, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, mtu)
	if err != nil {
		log.Fatal(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	if err = dev.IpcSet(fmt.Sprintf("private_key=%s", base64hex(privateKey))); err != nil {
		log.Fatal(err)
	}
	if err = dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0", base64hex(publicKey), endpoint)); err != nil {
		log.Fatal(err)
	}
	if err = dev.Up(); err != nil {
		log.Fatal(err)
	}

	server, err := socks5.New(&socks5.Config{
		Resolver: &resolver{tnet: tnet},
		Logger:   log.Default(),
		Dial:     tnet.DialContext,
	})
	if err != nil {
		log.Fatal(err)
	}

	if err = server.ListenAndServe("tcp", listen); err != nil {
		log.Fatal(err)
	}
}

func base64hex(s string) string {
	bin, _ := base64.StdEncoding.DecodeString(s)
	return hex.EncodeToString(bin)
}

type IPSlice []net.IP

func (ss *IPSlice) String() string {
	return fmt.Sprint(*ss)
}

func (ss *IPSlice) Set(value string) error {
	*ss = append(*ss, net.ParseIP(value))
	return nil
}

type resolver struct {
	tnet *netstack.Net
}

func (r *resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	hosts, err := r.tnet.LookupContextHost(ctx, name)
	if err != nil || len(hosts) < 1 {
		return ctx, nil, err
	}
	return ctx, net.ParseIP(hosts[0]), nil
}
