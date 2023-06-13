package utils

import (
	"net"
	"strings"
)

type Element interface {
	string | int | int32 | float32 | float64 | uint | uint32 | uint64
}

func GetInterFace() string {
	interfaces, _ := net.Interfaces()
	name := "eth0"
	for _, addr := range interfaces {
		addrs, err := addr.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addrs {
			// 检查ip地址判断是否回环地址
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
				name = addr.Name
				return name
			}
		}
	}
	return name
}
func InterfaceAddress(ifaceName string) string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic(err)
	}
	addr, err := iface.Addrs()
	if err != nil {
		panic(err)
	}
	addrStr := strings.Split(addr[0].String(), "/")[0]
	return addrStr
}
func InArray[T Element](needle T, haystack []T) bool {
	for _, v := range haystack {
		if needle == v {
			return true
		}
	}
	return false
}
