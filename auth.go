package net

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

const (
	Accept         = "Accept"
	ContentTypeKey = "Content-Type"
	CorsOrigin     = "Access-Control-Allow-Origin"
	CorsHeaders    = "Access-Control-Allow-Headers"
	CorsMethods    = "Access-Control-Allow-Methods"

	ApplicationJson = "application/json"
	Authorization   = "Authorization"

	ClientSecret       = "CLIENT_SECRET"
	TokenExpireMinutes = "TOKEN_EXPIRE_MINUTES"
	ValueCorsOrigin    = "CORS_ORIGIN"
)

type MiddlewareInterceptor func(http.ResponseWriter, *http.Request, http.HandlerFunc)
type MiddlewareHandlerFunc http.HandlerFunc
type MiddlewareChain []MiddlewareInterceptor

func (continuation MiddlewareHandlerFunc) Intercept(mw MiddlewareInterceptor) MiddlewareHandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		mw(writer, request, http.HandlerFunc(continuation))
	}
}

func (chain MiddlewareChain) Handler(handler http.HandlerFunc) http.HandlerFunc {
	curr := MiddlewareHandlerFunc(handler)
	for i := len(chain) - 1; i >= 0; i-- {
		mw := chain[i]
		curr = curr.Intercept(mw)
	}
	return http.HandlerFunc(curr)
}

func CorsMethodInterceptor(methods string) MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Set(CorsMethods, methods)
		next(w, r)
	}
}

func CorsAllInterceptor() MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Set(CorsOrigin, os.Getenv(ValueCorsOrigin))
		next(w, r)
	}
}

func ApplicationJsonInterceptor() MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Set(ContentTypeKey, ApplicationJson)
		next(w, r)
	}
}

func AuthenticationInterceptor() MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Add(CorsHeaders, Authorization)
		secret := os.Getenv(ClientSecret)
		err := Authenticate(r, secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func CreateToken(username string) (string, error) {
	secret := os.Getenv(ClientSecret)
	expiry, err := strconv.Atoi(os.Getenv(TokenExpireMinutes))
	if err != nil {
		return "", err
	}
	expireTime := time.Minute * time.Duration(expiry)
	claims := jwt.MapClaims{}
	claims["username"] = username
	claims["expires"] = time.Now().Add(expireTime).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func Authenticate(r *http.Request, secret string) error {
	bearerToken := r.Header.Get(Authorization)
	split := strings.Split(bearerToken, " ")
	if len(split) == 2 {
		tokenString := split[1]
		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		})
		return err
	}
	return fmt.Errorf("token not available")
}
