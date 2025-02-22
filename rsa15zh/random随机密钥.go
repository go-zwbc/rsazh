package rsa15zh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/yyle88/erero"
)

func R随机私钥(n位数 int) ([]byte, error) {
	// 通过指定 RSA 密钥的长度，例如 2048 位，生成 RSA 私钥
	pri, err := rsa.GenerateKey(rand.Reader, n位数)
	if err != nil {
		return nil, erero.Wro(err)
	}

	// 将私钥编码为 PKCS#8 格式的字节切片
	priBytes, err := x509.MarshalPKCS8PrivateKey(pri)
	if err != nil {
		return nil, erero.Wro(err)
	}

	return priBytes, nil
}

func R获得公钥(privateKeyBytes []byte) ([]byte, error) {
	// 解析 PKCS#8 格式的私钥字节切片
	prk, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, erero.Wro(err)
	}

	// 将私钥转换为 *rsa.PrivateKey 类型
	pri, ok := prk.(*rsa.PrivateKey)
	if !ok {
		return nil, erero.New("转换失败")
	}

	// 提取 RSA 公钥
	pub := pri.Public()

	// 将公钥编码为 PKIX 格式的字节切片
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, erero.Wro(err)
	}

	return pubBytes, nil
}
