package net_test

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	net "github.com/atulanand206/go-network"
	"github.com/dgrijalva/jwt-go/v4"
)

func ExampleCreateToken() {
	claims := jwt.MapClaims{}
	claims["name"] = "Judd"
	secret := "this is a secret key"
	expires := "1000"
	token, _ := net.CreateToken(claims, secret, expires)
	fmt.Println(token)
}

func ExampleCreateAccessToken() {
	claims := jwt.MapClaims{}
	claims["name"] = "Judd"
	secret := "this is a secret key"
	expires := "1000"
	os.Setenv("CLIENT_SECRET", secret)
	os.Setenv("TOKEN_EXPIRE_MINUTES", expires)
	token, _ := net.CreateAccessToken(claims)
	fmt.Println(token)
}

func ExampleCreateRefreshToken() {
	claims := jwt.MapClaims{}
	claims["name"] = "Judd"
	secret := "this is a secret key"
	expires := "1000"
	os.Setenv("REFRESH_CLIENT_SECRET", secret)
	os.Setenv("REFRESH_TOKEN_EXPIRE_MINUTES", expires)
	token, _ := net.CreateRefreshToken(claims)
	fmt.Println(token)
}

func ExampleAuthenticate() {
	claims := jwt.MapClaims{}
	claims["name"] = "Judd"
	secret := "this is a secret key"
	expires := "1000"
	token, _ := net.CreateToken(claims, secret, expires)

	r, _ := http.NewRequest(http.MethodGet, "", nil)
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	decryptedClaims, _ := net.Authenticate(r, secret)
	name := decryptedClaims["name"]
	fmt.Println(name)
	// Output:
	// Judd
}

func ExampleAuthenticateAccessToken() {
	claims := jwt.MapClaims{}
	claims["name"] = "Judd"
	secret := "this is a secret key"
	expires := "1000"
	os.Setenv("CLIENT_SECRET", secret)
	os.Setenv("TOKEN_EXPIRE_MINUTES", expires)
	token, _ := net.CreateAccessToken(claims)

	r, _ := http.NewRequest(http.MethodGet, "", nil)
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	decryptedClaims, _ := net.AuthenticateAccessToken(r)
	name := decryptedClaims["name"]
	fmt.Println(name)
	// Output :
	// Judd
}

func ExampleAuthenticateRefreshToken() {
	claims := jwt.MapClaims{}
	claims["name"] = "Judd"
	secret := "this is a secret key"
	expires := "1000"
	os.Setenv("REFRESH_CLIENT_SECRET", secret)
	os.Setenv("REFRESH_TOKEN_EXPIRE_MINUTES", expires)
	token, _ := net.CreateRefreshToken(claims)

	r, _ := http.NewRequest(http.MethodGet, "", nil)
	r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	decryptedClaims, _ := net.AuthenticateRefreshToken(r)
	name := decryptedClaims["name"]
	fmt.Println(name)
	// Output :
	// Judd
}

func TestToken(t *testing.T) {
	t.Run("it should have the same claims after decryption", func(t *testing.T) {
		claims := jwt.MapClaims{}
		claims["name"] = "Judd"
		secret := "this is a secret key"
		expires := "1000"
		token, _ := net.CreateToken(claims, secret, expires)

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
		decryptedClaims, _ := net.Authenticate(r, secret)
		name := decryptedClaims["name"]
		if name != "Judd" {
			t.Errorf("got %s, expected %s", name, "Judd")
		}
	})

	t.Run("it should return err when expiry time is not numeric", func(t *testing.T) {
		_, err := net.CreateToken(nil, "secret", "expires")
		if err == nil {
			t.Errorf("got no error, expected error")
		}
	})

	t.Run("it should return err when token is not available", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.Header.Add("Authorization", "Bearer")
		_, err := net.Authenticate(r, "secret")
		if err == nil {
			t.Errorf("got no error, expected error")
		}
	})
}

func TestAccessToken(t *testing.T) {
	t.Run("it should have the same claims after decryption", func(t *testing.T) {
		claims := jwt.MapClaims{}
		claims["name"] = "Judd"
		secret := "this is a secret key"
		expires := "1000"
		os.Setenv("CLIENT_SECRET", secret)
		os.Setenv("TOKEN_EXPIRE_MINUTES", expires)
		token, _ := net.CreateAccessToken(claims)

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
		decryptedClaims, _ := net.AuthenticateAccessToken(r)
		name := decryptedClaims["name"]
		if name != "Judd" {
			t.Errorf("got %s, expected %s", name, "Judd")
		}
	})
}

func TestRefreshToken(t *testing.T) {
	t.Run("it should have the same claims after decryption", func(t *testing.T) {
		claims := jwt.MapClaims{}
		claims["name"] = "Judd"
		secret := "this is a secret key"
		expires := "1000"
		os.Setenv("REFRESH_CLIENT_SECRET", secret)
		os.Setenv("REFRESH_TOKEN_EXPIRE_MINUTES", expires)
		token, _ := net.CreateRefreshToken(claims)

		r, _ := http.NewRequest(http.MethodGet, "", nil)
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
		decryptedClaims, _ := net.AuthenticateRefreshToken(r)
		name := decryptedClaims["name"]
		if name != "Judd" {
			t.Errorf("got %s, expected %s", name, "Judd")
		}
	})
}
