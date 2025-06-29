package rsa15zh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

type Rsa私钥 struct {
	pri *rsa.PrivateKey
}

func New私钥(pri *rsa.PrivateKey) *Rsa私钥 {
	return &Rsa私钥{pri: pri}
}

func (r *Rsa私钥) M签名(v明文 []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(v明文)
	return rsa.SignPKCS1v15(rand.Reader, r.pri, crypto.SHA256, hash.Sum(nil))
}

func (r *Rsa私钥) M解密(v密文 []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, r.pri, v密文)
}

func (r *Rsa私钥) P公钥() *Rsa公钥 {
	return New公钥(&r.pri.PublicKey)
}

type Rsa公钥 struct {
	pub *rsa.PublicKey
}

func New公钥(puk *rsa.PublicKey) *Rsa公钥 {
	return &Rsa公钥{pub: puk}
}

func (r *Rsa公钥) M加密(v明文 []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, r.pub, v明文)
}

func (r *Rsa公钥) M验签(v明文 []byte, v签名 []byte) error {
	hash := sha256.New()
	hash.Write(v明文)
	return rsa.VerifyPKCS1v15(r.pub, crypto.SHA256, hash.Sum(nil), v签名)
}
