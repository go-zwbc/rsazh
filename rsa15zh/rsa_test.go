package rsa15zh

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yyle88/must"
)

var case私钥 string
var case公钥 string

func TestMain(m *testing.M) {
	v私钥, err := R随机私钥(2048)
	must.Done(err)
	v公钥, err := R获得公钥(v私钥)
	must.Done(err)

	case私钥 = base64.StdEncoding.EncodeToString(v私钥)
	case公钥 = base64.StdEncoding.EncodeToString(v公钥)
	m.Run()
}

func TestF装载公钥(t *testing.T) {
	r公钥 := must装载公钥(t)
	v密文, err := r公钥.M加密([]byte("abc"))
	require.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(v密文))
}

func must装载公钥(t *testing.T) *Rsa公钥 {
	v公钥, err := base64.StdEncoding.DecodeString(case公钥)
	require.NoError(t, err)
	r公钥, err := F装载公钥(v公钥)
	require.NoError(t, err)
	return r公钥
}

func TestF装载私钥(t *testing.T) {
	r私钥 := must装载私钥(t)
	v密文, err := r私钥.M签名([]byte("xyz"))
	require.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(v密文))
}

func must装载私钥(t *testing.T) *Rsa私钥 {
	v私钥, err := base64.StdEncoding.DecodeString(case私钥)
	require.NoError(t, err)
	r私钥, err := F装载私钥(v私钥)
	require.NoError(t, err)
	return r私钥
}

func TestRsa公钥_M加密(t *testing.T) {
	r公钥 := must装载公钥(t)
	v密文, err := r公钥.M加密([]byte("abc"))
	require.NoError(t, err)

	r私钥 := must装载私钥(t)
	v明文, err := r私钥.M解密(v密文)
	require.NoError(t, err)

	require.Equal(t, "abc", string(v明文))
}

func TestRsa私钥_M签名(t *testing.T) {
	r私钥 := must装载私钥(t)
	v密文, err := r私钥.M签名([]byte("xyz"))
	require.NoError(t, err)

	r公钥 := must装载公钥(t)
	err = r公钥.M验签([]byte("xyz"), v密文)
	require.NoError(t, err)
}

func TestRsa私钥_P公钥(t *testing.T) {
	r私钥 := must装载私钥(t)
	v密文, err := r私钥.M签名([]byte("xyz"))
	require.NoError(t, err)

	r公钥 := r私钥.P公钥()
	err = r公钥.M验签([]byte("xyz"), v密文)
	require.NoError(t, err)
}

func TestRsa私钥_B导出(t *testing.T) {
	r私钥 := must装载私钥(t)
	data, err := r私钥.B导出()
	require.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(data))
}

func TestRsa公钥_B导出(t *testing.T) {
	r公钥 := must装载公钥(t)
	data, err := r公钥.B导出()
	require.NoError(t, err)
	t.Log(base64.StdEncoding.EncodeToString(data))
}
