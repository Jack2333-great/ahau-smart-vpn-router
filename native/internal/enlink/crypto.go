package enlink

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

// EncryptPassword follows the SDK's AES/CBC/PKCS5Padding wire format.
// The server supplies the key; the IV is the reversed ASCII key.
func EncryptPassword(password, key string) (string, error) {
	if len(key) != 16 {
		return "", fmt.Errorf("unexpected authentication key length: %d", len(key))
	}
	for _, c := range []byte(key) {
		if c > 127 {
			return "", fmt.Errorf("non-ASCII authentication key")
		}
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	iv := []byte(key)
	for i, j := 0, len(iv)-1; i < j; i, j = i+1, j-1 {
		iv[i], iv[j] = iv[j], iv[i]
	}
	plain := []byte(password)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	clear(plain)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}
