package icmp

import (
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func Icmp(ip string) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 255,
			Seq:  1,
			Data: []byte(""),
		},
	}
	marshal, _ := msg.Marshal(nil)
	c, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		return false
	}
	c.SetReadDeadline(time.Now().Add(1 * time.Second))
	defer c.Close()
	_, err2 := c.Write(marshal)
	if err2 != nil {
		return false
	}
	buf := make([]byte, 1500)
	_, err = c.Read(buf)
	return err == nil
}
