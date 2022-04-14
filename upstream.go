package trojan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/wen-long/caddy-trojan/trojan"
	"github.com/wen-long/caddy-trojan/utils"
)

// Traffic is ...
type Traffic struct {
	// Up is ...
	Up int64 `json:"up"`
	// Down is ...
	Down int64 `json:"down"`
}

// Upstream is ...
type Upstream struct {
	// Prefix is ...
	Prefix string
	// Storage is ...
	Storage certmagic.Storage
	// Logger is ...
	Logger *zap.Logger
}

// NewUpstream is ...
func NewUpstream(st certmagic.Storage, lg *zap.Logger) *Upstream {
	return &Upstream{
		Prefix:  "",
		Storage: st,
		Logger:  lg,
	}
}

// AddKey is ...
func (u *Upstream) AddKey(k string) error {
	key := u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	if u.Storage.Exists(context.Background(), key) {
		return nil
	}
	traffic := Traffic{
		Up:   0,
		Down: 0,
	}
	b, err := json.Marshal(&traffic)
	if err != nil {
		return err
	}
	return u.Storage.Store(context.Background(), key, b)
}

// Add is ...
func (u *Upstream) Add(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	return u.AddKey(utils.ByteSliceToString(b[:]))
}

// DelKey is ...
func (u *Upstream) DelKey(k string) error {
	key := u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	if !u.Storage.Exists(context.Background(), key) {
		return nil
	}
	return u.Storage.Delete(context.Background(), key)
}

// Del is ...
func (u *Upstream) Del(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	return u.DelKey(utils.ByteSliceToString(b[:]))
}

// Range is ...
func (u *Upstream) Range(fn func(k string, up, down int64)) {
	// base64.StdEncoding.EncodeToString(hex.Encode(sha256.Sum224([]byte("Test1234"))))
	const AuthLen = 76

	keys, err := u.Storage.List(context.Background(), u.Prefix, false)
	if err != nil {
		return
	}

	traffic := Traffic{}
	for _, k := range keys {
		b, err := u.Storage.Load(context.Background(), k)
		if err != nil {
			u.Logger.Error(fmt.Sprintf("load user error: %v", err))
			continue
		}
		if err := json.Unmarshal(b, &traffic); err != nil {
			u.Logger.Error(fmt.Sprintf("load user error: %v", err))
			continue
		}
		fn(strings.TrimPrefix(k, u.Prefix), traffic.Up, traffic.Down)
	}

	return
}

// Validate is ...
func (u *Upstream) Validate(k string) bool {
	// base64.StdEncoding.EncodeToString(hex.Encode(sha256.Sum224([]byte("Test1234"))))
	const AuthLen = 76
	if len(k) == AuthLen {
		k = u.Prefix + k
	} else {
		k = u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	}
	fmt.Printf("Validate key: %s\n", k)
	return u.Storage.Exists(context.Background(), k)
}

// Consume is ...
func (u *Upstream) Consume(k string, nr, nw int64) error {
	// base64.StdEncoding.EncodeToString(hex.Encode(sha256.Sum224([]byte("Test1234"))))
	const AuthLen = 76
	if len(k) == AuthLen {
		k = u.Prefix + k
	} else {
		k = u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	}

	u.Storage.Lock(context.Background(), k)
	defer u.Storage.Unlock(context.Background(), k)

	b, err := u.Storage.Load(context.Background(), k)
	if err != nil {
		return err
	}

	traffic := Traffic{}
	if err := json.Unmarshal(b, &traffic); err != nil {
		return err
	}

	traffic.Up += nr
	traffic.Down += nw

	b, err = json.Marshal(&traffic)
	if err != nil {
		return err
	}

	return u.Storage.Store(context.Background(), k, b)
}
