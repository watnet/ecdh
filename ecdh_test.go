package ecdh_test

import (
	"crypto/ed25519"
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pub1, priv1, err := ed25519.GenerateKey(nil)
			require.NoError(t, err, "It should generate keys.")

			pub2, priv2, err := ed25519.GenerateKey(nil)
			require.NoError(t, err, "It should generate keys.")

			enc, err := ecdh.Encrypt(nil, test.data, priv1, pub2)
			require.NoError(t, err, "It should encrypt the data.")
			require.NotEqual(t, test.data, enc, "The encrypted data should be different from the original.")

			dec, err := ecdh.Decrypt(nil, enc, priv2, pub1)
			require.NoError(t, err, "It should decrypt the data.")

			require.Equal(t, test.data, dec, "The decrypted data should be the same as before encryption.")
		})
	}
}
