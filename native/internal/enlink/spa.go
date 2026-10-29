package enlink

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5" // Required by the installed Enlink wire protocol.
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

// SPAOptions describes the legacy Enlink format confirmed against libfko.dll.
// PasswordMaterial is the SDK's PasswdStr, not the campus account password.
// The Android initializer represents a configured shared secret as MD5 hex.
type SPAOptions struct{ Username, Access, PasswordMaterial string }

// Deployment bootstrap from the school's downloadable APK, unrelated to
// campus account credentials. The SDK initializer passes MD5 hex to libfko.
func SchoolAPKPasswordMaterial() string {
	d := md5.Sum([]byte("Enlink@123"))
	return hex.EncodeToString(d[:])
}
func (r Rules) SPAEndpoint(g Gateway) (address, access string, err error) {
	fields := strings.Split(r.Server, "||")
	if len(fields) != 3 {
		return "", "", errors.New("SPA requires the published transport and door port")
	}
	host, _, e := net.SplitHostPort(fields[1])
	if e != nil || net.ParseIP(host) == nil {
		return "", "", errors.New("invalid published SPA address")
	}
	port := g.SPAPort
	if port == "" {
		port = r.SPAPort
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return "", "", errors.New("invalid published SPA UDP port")
	}
	door, e := strconv.Atoi(fields[2])
	if e != nil || door < 1 || door > 65535 {
		return "", "", errors.New("invalid published SPA door port")
	}
	return net.JoinHostPort(host, port), "tcp/" + fields[2], nil
}

func NewSPAPacket(options SPAOptions) ([]byte, error) {
	var nonce strings.Builder
	for i := 0; i < 16; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return nil, err
		}
		nonce.WriteByte(byte(n.Int64()) + '0')
	}
	var salt [8]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, err
	}
	return encodeSPA(options, nonce.String(), time.Now().Unix(), salt)
}
func ValidateSPAUsername(username string) error {
	if len(username) < 1 || len(username) > 64 || strings.ContainsAny(username, ":\r\n\x00") {
		return errors.New("invalid SPA username")
	}
	for _, c := range []byte(username) {
		if c < 33 || c > 126 {
			return errors.New("SPA username must be printable ASCII")
		}
	}
	return nil
}
func encodeSPA(o SPAOptions, nonce string, timestamp int64, salt [8]byte) ([]byte, error) {
	if err := ValidateSPAUsername(o.Username); err != nil {
		return nil, err
	}
	if len(nonce) != 16 || strings.Trim(nonce, "0123456789") != "" || timestamp <= 0 {
		return nil, errors.New("invalid SPA nonce/time")
	}
	if !strings.HasPrefix(o.Access, "tcp/") {
		return nil, errors.New("only server-published TCP door ports supported")
	}
	p, err := strconv.Atoi(strings.TrimPrefix(o.Access, "tcp/"))
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("invalid SPA access port")
	}
	if o.PasswordMaterial == "" || len(o.PasswordMaterial) > 1024 {
		return nil, errors.New("SPA password material missing/too long")
	}
	b64 := base64.RawStdEncoding
	encoded := fmt.Sprintf("%s:%s:%d:3.0.0:1:%s", nonce, b64.EncodeToString([]byte(o.Username)), timestamp, b64.EncodeToString([]byte("0.0.0.0,"+o.Access)))
	digest := sha256.Sum256([]byte(encoded))
	plain := []byte(encoded + ":" + b64.EncodeToString(digest[:]) + ":enlink")
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	defer clear(plain)
	password := md5.Sum([]byte(o.PasswordMaterial))
	defer clear(password[:])
	// OpenSSL-compatible EVP_BytesToKey with MD5, 8-byte salt, one round.
	// Protocol compatibility requires AES-256 even though the input is 16 bytes.
	var derived []byte
	var previous []byte
	for len(derived) < 48 {
		hash := md5.New()
		hash.Write(previous)
		hash.Write(password[:])
		hash.Write(salt[:])
		previous = hash.Sum(nil)
		derived = append(derived, previous...)
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, 16+len(plain))
	copy(encrypted, "Salted__")
	copy(encrypted[8:16], salt[:])
	cipher.NewCBCEncrypter(block, derived[32:48]).CryptBlocks(encrypted[16:], plain)
	full := b64.EncodeToString(encrypted)
	mac := hmac.New(sha256.New, password[:])
	mac.Write([]byte(full))
	// Prefix removal applies to the full base64 string, after its HMAC.
	return []byte(full[10:] + b64.EncodeToString(mac.Sum(nil)) + "enlink"), nil
}
func SendSPA(ctx context.Context, address string, packet []byte) error {
	if len(packet) < 100 || len(packet) > 1500 {
		return errors.New("invalid SPA packet size")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "udp", address)
	if err != nil {
		return errors.New("SPA UDP destination unavailable")
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	n, err := conn.Write(packet)
	if err != nil || n != len(packet) {
		return errors.New("SPA UDP send failed")
	}
	return nil
}
