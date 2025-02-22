package rsa15zh

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestR随机私钥(t *testing.T) {
	v私钥, err := R随机私钥(2048)
	require.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(v私钥))
}

func TestR获得公钥(t *testing.T) {
	v私钥, err := R随机私钥(4096)
	require.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(v私钥))

	v公钥, err := R获得公钥(v私钥)
	require.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(v公钥))
}
