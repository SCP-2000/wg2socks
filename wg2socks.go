package main

import (
	"context"
	"flag"
	"github.com/armon/go-socks5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	configFile := flag.String("c", "wg.yaml", "path to wg-quick config")
	flag.Parse()

	confData, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := ConfigFromYAML(confData)
	if err != nil {
		log.Fatal(err)
	}

	var localAddr []net.IP
	for _, cidr := range cfg.Interface.Address {
		localAddr = append(localAddr, cidr.IP)
	}

	tun, tnet, err := netstack.CreateNetTUN(localAddr, cfg.Interface.DNS, int(cfg.Interface.MTU))
	if err != nil {
		log.Fatal(err)
	}

	bind := conn.NewDefaultBind()
	if cfg.Interface.ListenPort != 0 {
		_, err = bind.Open(cfg.Interface.ListenPort)
		if err != nil {
			log.Fatal(err)
		}
	}
	if cfg.Interface.FwMark != 0 {
		err = bind.SetMark(cfg.Interface.FwMark)
		if err != nil {
			log.Fatal(err)
		}
	}

	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelError, ""))

	uapi, err := cfg.ToUAPI()
	if err != nil {
		log.Fatal(err)
	}

	if err = dev.IpcSet(uapi); err != nil {
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

	lis := net.UDPAddr(cfg.Listen)
	if err = server.ListenAndServe("tcp", (&lis).String()); err != nil {
		log.Fatal(err)
	}
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
