package wgnet

import (
	"context"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func (c *Config) Instantiate(ctx context.Context) (*netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN(c.Interface.Address, c.Interface.DNS, int(c.Interface.MTU))
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = tun.Close()
	}()

	bind := conn.NewDefaultBind()
	go func() {
		<-ctx.Done()
		_ = bind.Close()
	}()
	_, err = bind.Open(c.Interface.ListenPort)
	if err != nil {
		return nil, err
	}

	if c.Interface.FirewallMark != 0 {
		err = bind.SetMark(c.Interface.FirewallMark)
		if err != nil {
			return nil, err
		}
	}

	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelError, ""))
	go func() {
		<-ctx.Done()
		dev.Close()
	}()
	uapi, err := c.ToUAPI()
	if err != nil {
		return nil, err
	}
	err = dev.IpcSet(uapi)
	if err != nil {
		return nil, err
	}
	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return tnet, nil
}
