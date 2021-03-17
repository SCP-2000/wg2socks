package main

import (
	"context"
	"flag"
	"github.com/SCP-2000/wg2socks/pkg/wgquick"
	"github.com/thinkgos/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	var configFile = flag.String("c", "wg0.conf", "path to wg-quick config")
	var listen = flag.String("l", "127.0.0.1:1080", "socks5 server listen address")
	flag.Parse()
	data, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := wgquick.ParseWGQuick(data)
	if err != nil {
		log.Fatal(err)
	}
	tnet, err := cfg.Instantiate(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	server := socks5.NewServer(socks5.WithDial(tnet.DialContext), socks5.WithResolver(&resolver{tnet: tnet}))
	err = server.ListenAndServe("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
}

type resolver struct {
	tnet *netstack.Net
}

func (r *resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := r.tnet.LookupContextHost(ctx, name)
	if err != nil || len(addrs) < 1 {
		return ctx, nil, err
	}
	return ctx, net.ParseIP(addrs[0]), err
}
