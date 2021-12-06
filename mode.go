package ecdh

import (
	"crypto/aes"
	"crypto/cipher"
)

// Mode represents the symmetric encryption scheme to be used.
type Mode interface {
	// TODO: Find a way to make this work for various cipher types.
	cipher(key []byte) (cipher.Block, error)
	blockSize() int
}

type aesMode struct{}

func AES() Mode {
	return aesMode{}
}

func (aesMode) cipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func (aesMode) blockSize() int {
	return aes.BlockSize
}
