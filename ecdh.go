package ecdh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
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
// provided public and private Ed25519 keys. It appends the result to
// out and returns the resulting slice.
func Decrypt(out, data []byte, priv ed25519.PrivateKey, pub ed25519.PublicKey) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrDataLen
	}

	key, err := curve25519.X25519(priv.Seed(), pub)
	if err != nil {
		return nil, fmt.Errorf("calculate key: %w", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	d := cipher.NewCBCDecrypter(c, data[:aes.BlockSize])

	data = data[aes.BlockSize:]

	start := len(out)
	out = append(out, data...)
	d.CryptBlocks(out[start:], data)

	return out, nil
}

// Encrypt encrypts data using an AES key generated via ECDH from the
// provided public and private Ed25519 keys. It appends the result to
// out and returns the resulting slice.
func Encrypt(out, data []byte, priv ed25519.PrivateKey, pub ed25519.PublicKey) ([]byte, error) {
	key, err := curve25519.X25519(priv.Seed(), pub)
	if err != nil {
		return nil, fmt.Errorf("calculate key: %w", err)
	}

	pad := len(data) % aes.BlockSize
	start := len(out)
	out = append(out, make([]byte, aes.BlockSize+len(data)+pad)...)
	_, err = io.ReadFull(rand.Reader, out[start:aes.BlockSize])
	if err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	d := cipher.NewCBCEncrypter(c, out[start:aes.BlockSize])

	if pad != 0 {
		_, err := io.ReadFull(rand.Reader, data[len(data)-pad:])
		if err != nil {
			return nil, fmt.Errorf("generate padding: %w", err)
		}
	}

	d.CryptBlocks(out[start+aes.BlockSize:], data)

	return out, nil
}
