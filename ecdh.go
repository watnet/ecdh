package ecdh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

var (
	ErrDataLen = errors.New("data length zero or not a multiple of the blocksize")
)

// Decrypt decrypts data using an AES key generated via ECDH from the
// provided public and private Ed25519 keys.
func Decrypt(data, priv, pub []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrDataLen
	}

	key, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("calculate key: %w", err)
	}

	iv := data[:aes.BlockSize]
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	d := cipher.NewCBCDecrypter(c, iv)

	data = data[aes.BlockSize:]
	out := make([]byte, len(data))
	d.CryptBlocks(out, data)

	return out, nil
}

// Encrypt encrypts data using an AES key generated via ECDH from the
// provided public and private Ed25519 keys.
func Encrypt(data, priv, pub []byte) ([]byte, error) {
	key, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("calculate key: %w", err)
	}

	pad := aes.BlockSize - len(data)%aes.BlockSize
	out := make([]byte, aes.BlockSize+len(data)+pad)
	_, err = io.ReadFull(rand.Reader, out[:aes.BlockSize])
	if err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	d := cipher.NewCBCEncrypter(c, out[:aes.BlockSize])

	if pad != 0 {
		_, err := io.ReadFull(rand.Reader, data[len(data)-pad:])
		if err != nil {
			return nil, fmt.Errorf("generate padding: %w", err)
		}
	}

	d.CryptBlocks(out[aes.BlockSize:], data)

	return out, nil
}
