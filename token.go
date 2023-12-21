package saramaoauthjwtbearer

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/IBM/sarama"

	"github.com/dgrijalva/jwt-go"
)

type Confg struct {
	ClientID string
	Audience string
	TokenURL string
	PkPath   string
	Scope    string
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func LoadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := os.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func GenerateToken(p *Confg) (string, error) {
	keyData, _ := os.ReadFile(p.PkPath)
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", err
	}
	claims := &jwt.StandardClaims{
		Issuer:    p.ClientID,
		Subject:   p.ClientID,
		Audience:  p.Audience,
		ExpiresAt: int64(time.Now().Add(time.Duration(5 * time.Minute)).Unix()),
		Id:        randSeq(32),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	//token.Header["x5t"] = ""
	ss, err := token.SignedString(key)

	if err != nil {
		return "", err
	}
	params := url.Values{}
	params.Add("client_assertion", ss)
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("scope", p.Scope)
	params.Add("grant_type", "client_credentials")

	var req *http.Request
	req, err = http.NewRequest("POST", p.TokenURL, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	var body []byte
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.Audience, body)
		return "", err
	}
	// Get the token from the body that we got from the token endpoint.
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return "", err
	}
	//fmt.Println(jsonResponse.AccessToken)
	return jsonResponse.AccessToken, nil
}

type JWTBTokenProvider struct {
	Cfg Confg
}

func (t *JWTBTokenProvider) Token() (*sarama.AccessToken, error) {
	token, err := GenerateToken(&t.Cfg)
	if err != nil {
		return nil, err
	}
	return &sarama.AccessToken{Token: token}, nil
}
