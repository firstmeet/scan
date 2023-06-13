package scan

import (
	"testing"
	"time"
)

func TestNewScan(t *testing.T) {
	rev := make(chan Result, 100)
	s := NewScan([]string{"223.75.159.31"}, []int{22, 23, 2222}, 10, 10*time.Second, rev)
	go func() {
		for result := range rev {
			t.Logf("[*] %s/%d is open\n", result.Ip, result.Port)
		}
	}()
	s.Start()
	s.Wait()
}
