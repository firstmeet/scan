package scan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/firstmeet/scan/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Scan struct {
	IpList        []string
	PortList      []int
	ThreadNum     int
	Timeout       time.Duration
	ListenStatus  bool
	hanPermission bool
	seq           int
	laddr         string
	Result        chan Result
	finish        chan struct{}
	maxCh         chan struct{}
	closeListen   chan struct{}
	aliveIP       []string
	ReturnNumber  int
	start         chan struct{}
	Total         int
	Lock          sync.Mutex
}
type Result struct {
	Ip   string
	Port int
}

func NewScan(IpList []string, PortList []int, ThreadNum int, Timeout time.Duration, Result chan Result) *Scan {
	rand.Seed(time.Now().UnixNano())
	return &Scan{
		IpList:        IpList,
		PortList:      PortList,
		ThreadNum:     ThreadNum,
		Timeout:       Timeout,
		start:         make(chan struct{}, 10),
		laddr:         utils.InterfaceAddress(utils.GetInterFace()),
		Result:        Result,
		hanPermission: checkPermission(),
		finish:        make(chan struct{}),
		seq:           rand.Intn(65535),
		aliveIP:       make([]string, 0),
		maxCh:         make(chan struct{}, ThreadNum),
		closeListen:   make(chan struct{}),
		ReturnNumber:  0,
		Total:         0,
		Lock:          sync.Mutex{},
	}
}
func (scan *Scan) Start() {
	if scan.hanPermission {
		fmt.Printf("[*] Start SYN scan\n")
		go scan.scan_syn()
	} else {
		fmt.Printf("[*] Start CONNECT scan\n")
		go scan.scan_connect()
	}
}
func (scan *Scan) scan_syn() {
	go func() {
		i, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(scan.laddr)})
		if err != nil {
			return
		}
		scan.ListenStatus = true
		timer := time.NewTimer(scan.Timeout)
		defer i.Close()
		for {
			select {
			case <-timer.C:
				scan.finish <- struct{}{}
				return
			case <-scan.closeListen:
				return
			default:
				buf := make([]byte, 100)
				_, addr, err := i.ReadFrom(buf)
				if err != nil {
					panic(err)
				}
				var port uint16
				binary.Read(bytes.NewReader(buf[0:2]), binary.BigEndian, &port)
				var ack uint32
				binary.Read(bytes.NewReader(buf[8:12]), binary.BigEndian, &ack)
				if utils.InArray(addr.String(), scan.IpList) && utils.InArray[int](int(port), scan.PortList) && ack == uint32(scan.seq)+1 {
					scan.ReturnNumber++
					if buf[13] == 0x12 {
						scan.Result <- Result{
							Ip:   addr.String(),
							Port: int(port),
						}
					}
					fmt.Printf("[*] get %d,total %d\n", scan.ReturnNumber, scan.Total)
					if scan.ReturnNumber >= scan.Total {
						go func() {
							scan.finish <- struct{}{}
						}()
						return
					}
					timer.Reset(scan.Timeout)
				}
			}

		}
	}()
	go func() {
		<-scan.start
		fmt.Println("[*] Start scan")
		scan.Lock.Lock()
		scan.Total = len(scan.aliveIP) * len(scan.PortList)
		scan.Lock.Unlock()
		for i := 0; i < len(scan.aliveIP); i++ {
			for j := 0; j < len(scan.PortList); j++ {
				go scan.scan(scan.aliveIP[i], scan.PortList[j])
			}
		}
	}()
	go scan.alive()
}
func (scan *Scan) scan_connect() {
	wg := sync.WaitGroup{}
	for i := 0; i < len(scan.IpList); i++ {
		for j := 0; j < len(scan.PortList); j++ {
			wg.Add(1)
			go func(ip string, port int, wg *sync.WaitGroup) {
				defer wg.Done()
				scan.scan_connect_port(ip, port)
			}(scan.IpList[i], scan.PortList[j], &wg)
		}
	}
	wg.Wait()
	go func() {
		scan.finish <- struct{}{}
	}()
}
func (scan *Scan) scan_connect_port(ip string, port int) {
	scan.maxCh <- struct{}{}
	defer func() {
		<-scan.maxCh
	}()
	fmt.Printf("[*]start scan %s:%d\n", ip, port)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), scan.Timeout)
	if err != nil {
		// fmt.Printf("scan %s:%d error:%s\n", ip, port, err.Error())
		return
	}
	conn.Close()
	scan.Result <- Result{
		Ip:   ip,
		Port: port,
	}
}
func (scan *Scan) scan(ip string, port int) {
	scan.maxCh <- struct{}{}
	defer func() {
		<-scan.maxCh
	}()
	err := scan.scanPort(ip, port)
	if err != nil {
		// fmt.Printf("scan %s:%d error:%s\n", ip, port, err.Error())
		return
	}

}
func (scan *Scan) scanPort(ip string, port int) error {
	//TODO
	//use gopacket to send tcp syn packet to scan port alive
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(rand.Intn(65535)),
		DstPort: layers.TCPPort(port),
		SYN:     true,
		Window:  14600,
		Seq:     uint32(scan.seq),
	}
	ipLayer := &layers.IPv4{
		DstIP: net.ParseIP(ip),
		SrcIP: net.ParseIP(scan.laddr),
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()
	option := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err := gopacket.SerializeLayers(buffer, option, tcpLayer)
	if err != nil {
		return err
	}
	packetData := buffer.Bytes()
	conn, err := net.DialTimeout("ip4:tcp", ip, scan.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(packetData)
	return err
}
func (scan *Scan) Close() {
	close(scan.Result)
}
func (scan *Scan) Wait() {
	<-scan.finish
}
func (scan *Scan) CloseListen() {
	scan.closeListen <- struct{}{}
	scan.ListenStatus = false
}
func (scan *Scan) alive() {
	wg := sync.WaitGroup{}
	for i := 0; i < len(scan.IpList); i++ {
		wg.Add(1)
		go func(i int, wg *sync.WaitGroup) {
			defer wg.Done()
			scan.alive_send(strings.TrimSpace(scan.IpList[i]))
		}(i, &wg)
	}
	wg.Wait()
	fmt.Printf("[*] alive finish\n")
	scan.start <- struct{}{}
}
func (scan *Scan) alive_send(ip string) {
	scan.maxCh <- struct{}{}
	defer func() {
		<-scan.maxCh
	}()
	b := icmp_send(ip)
	if b {
		scan.Lock.Lock()
		scan.aliveIP = append(scan.aliveIP, ip)
		scan.Lock.Unlock()
	}
}
func icmp_send(ip string) bool {
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

// check has operate permission
func checkPermission() bool {
	//TODO
	//check whether has operate permission
	i, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return false
	}
	defer i.Close()
	return true
}
