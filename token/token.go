package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	TokenTimeout = 3000 // 50 minutes
)

type Token struct {
	AuthKey  *ecdsa.PrivateKey
	KeyID    string
	TeamID   string
	IssuedAt int64
	Bearer   string
	m        sync.Mutex
}

func AuthKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return AuthKeyFromBytes(bytes)
}

func AuthKeyFromBytes(bytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pk := key.(type) {
	case *ecdsa.PrivateKey:
		return pk, nil
	default:
		return nil, errors.New("token: AuthKey must be of type ecdsa.PrivateKey")
	}
}

func (t *Token) GenerateIfExpired() {
	t.m.Lock()
	defer t.m.Unlock()
	if t.Expired() {
		t.Generate()
	}
}

func (t *Token) Expired() bool {
	return time.Now().Unix() >= (t.IssuedAt + TokenTimeout)
}

func (t *Token) Generate() (bool, error) {
	issuedAt := time.Now().Unix()
	jwtToken := &jwt.Token{
		Header: map[string]interface{}{
			"alg": "ES256",
			"kid": t.KeyID,
		},
		Claims: jwt.MapClaims{
			"iss": t.TeamID,
			"iat": issuedAt,
		},
		Method: jwt.SigningMethodES256,
	}
	bearer, err := jwtToken.SignedString(t.AuthKey)
	if err != nil {
		return false, err
	}
	t.IssuedAt = issuedAt
	t.Bearer = bearer
	return true, nil
}
