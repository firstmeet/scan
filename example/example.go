package example

import (
	"fmt"
	"time"

	"github.com/firstmeet/scan"
)

func Example() {
	ipList := []string{"127.0.0.1", "192.168.1.1"}
	portList := []int{22, 23, 3306}
	rev := make(chan scan.Result, 100)
	s := scan.NewScan(ipList, portList, 100, 10*time.Second, rev)
	go func() {
		for result := range rev {
			fmt.Printf("[*] %s/%d is open\n", result.Ip, result.Port)
		}
	}()
	s.Start()
	s.Wait()
}
