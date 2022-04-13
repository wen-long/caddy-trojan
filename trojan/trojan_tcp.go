package trojan

import (
	"context"
	"fmt"
	"io"
	"time"

	"golang.org/x/net/proxy"
)

// HandleTCP is ...
// trojan TCP stream
func HandleTCP(r io.Reader, w io.Writer, addr string) (int64, int64, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()
	rc, err := proxy.Dial(ctx, "tcp", addr)
	if err != nil {
		return 0, 0, err
	}
	defer rc.Close()

	var nr, nw int64 = 0, 0
	done := make(chan int, 0)
	go func() {
		n, _ := io.Copy(rc, r)
		nr += n
		_ = rc.Close()
		done <- 1
	}()
	n, _ := io.Copy(w, rc)
	nw += n
	_ = rc.Close()
	<-done
	fmt.Printf("trojan tcp to %s upload %d bytes, download %d bytes\n", addr, nr, nw)
	return nr, nw, err
}
