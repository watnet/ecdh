package ecdh_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/watnet/ecdh"
)

var config = ecdh.Config{}

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

			priv1, err := config.GenerateKey()
			require.NoError(t, err, "It should generate a private key.")
			pub1, err := priv1.PublicKey()
			require.NoError(t, err, "It should calculate the public key.")

			priv2, err := config.GenerateKey()
			require.NoError(t, err, "It should generate a private key.")
			pub2, err := priv2.PublicKey()
			require.NoError(t, err, "It should calculate the public key.")

			enc := make([]byte, config.EncryptedLen(len(test.data)))
			err = config.Encrypt(enc, test.data, priv1, pub2)
			require.NoError(t, err, "It should encrypt the data.")
			require.NotEqual(t, test.data, enc, "The encrypted data should be different from the original.")

			dec := make([]byte, config.DecryptedLen(len(enc)))
			err = config.Decrypt(dec, enc, priv2, pub1)
			require.NoError(t, err, "It should decrypt the data.")

			pad := config.PaddingLen(len(test.data))
			require.Equal(t, len(test.data)+pad, len(dec), "The decrypted data should be the original length plus padding.")

			require.Equal(t, test.data, dec[:len(test.data)], "The decrypted data should be the same as before encryption.")
		})
	}
}
