package ecdh_test

import (
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

			priv1, err := ecdh.GenerateKey(nil)
			require.NoError(t, err, "It should generate a private key.")
			pub1, err := ecdh.GetPublic(priv1)
			require.NoError(t, err, "It should calculate the public key.")

			priv2, err := ecdh.GenerateKey(nil)
			require.NoError(t, err, "It should generate a private key.")
			pub2, err := ecdh.GetPublic(priv2)
			require.NoError(t, err, "It should calculate the public key.")

			enc, err := ecdh.Encrypt(nil, test.data, priv1, pub2)
			require.NoError(t, err, "It should encrypt the data.")
			require.NotEqual(t, test.data, enc, "The encrypted data should be different from the original.")

			dec, err := ecdh.Decrypt(nil, enc, priv2, pub1)
			require.NoError(t, err, "It should decrypt the data.")

			require.Equal(t, test.data, dec, "The decrypted data should be the same as before encryption.")
		})
	}
}
