package net

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

const (
	ContentTypeKey  = "content-type"
	Cors            = "Access-Control-Allow-Origin"
	ApplicationJson = "application/json"
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

func CorsAllInterceptor() MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Set(Cors, "*")
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
		secret := os.Getenv("CLIENT_SECRET")
		err := Authenticate(r, secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func CreateToken(username string, secret string, expiry int) (string, error) {
	expireTime := time.Minute * time.Duration(expiry)
	claims := jwt.MapClaims{}
	claims["userName"] = username
	claims["expires"] = time.Now().Add(expireTime).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func Authenticate(r *http.Request, secret string) error {
	bearerToken := r.Header.Get("Authorization")
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
