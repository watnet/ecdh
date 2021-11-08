package ecdh_test

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/watnet/ecdh"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "NoPadding",
			data: []byte("testbutnopadding"),
		},
		{
			name: "Padding",
			data: []byte("testwithpadding"),
		},
		{
			name: "LongWithPadding",
			data: []byte("this is some text that is longer than a single block and has padding"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			priv1, err := ecdh.GenerateKey(nil)
			require.NoError(t, err, "It should generate a private key.")
			pub1, err := ecdh.PublicKey(priv1)
			require.NoError(t, err, "It should calculate the public key.")

			priv2, err := ecdh.GenerateKey(nil)
			require.NoError(t, err, "It should generate a private key.")
			pub2, err := ecdh.PublicKey(priv2)
			require.NoError(t, err, "It should calculate the public key.")

			enc, err := ecdh.Encrypt(nil, test.data, priv1, pub2, nil)
			require.NoError(t, err, "It should encrypt the data.")
			require.NotEqual(t, test.data, enc, "The encrypted data should be different from the original.")

			dec, err := ecdh.Decrypt(nil, enc, priv2, pub1)
			require.NoError(t, err, "It should decrypt the data.")

			pad := (aes.BlockSize - len(test.data)%aes.BlockSize) % aes.BlockSize
			require.Equal(t, len(test.data)+pad, len(dec), "The decrypted data should be the original length plus padding.")

			require.Equal(t, test.data, dec[:len(test.data)], "The decrypted data should be the same as before encryption.")
		})
	}
}
