//go:build go1.18
// +build go1.18

package ecdh_test

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/watnet/ecdh"
)

func FuzzECDH(f *testing.F) {
	f.Fuzz(func(t *testing.T, input []byte) {
		priv1, err := ecdh.GenerateKey(nil)
		require.NoError(t, err, "It should generate the first private key.")
		pub1, err := ecdh.PublicKey(priv1)
		require.NoError(t, err, "It should calculate the first public key.")

		priv2, err := ecdh.GenerateKey(nil)
		require.NoError(t, err, "It should generate the first private key.")
		pub2, err := ecdh.PublicKey(priv2)
		require.NoError(t, err, "It should calculate the first public key.")

		enc, err := ecdh.Encrypt(nil, input, priv1, pub2, nil)
		require.NoError(t, err, "It should encrypt the data.")

		dec, err := ecdh.Decrypt(nil, enc, priv2, pub1)
		require.NoError(t, err, "It should decrypt the data.")

		if (len(input) == 0) && (len(enc) == aes.BlockSize) && (len(dec) == 0) {
			t.Skip()
		}

		pad := ecdh.PaddingLen(len(input))
		require.Equal(t, input, dec[:len(dec)-pad], "The decrypted data should be the same as the input.")
	})
}
