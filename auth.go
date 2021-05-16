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
	// Headers keys
	Accept         = "Accept"
	ContentTypeKey = "Content-Type"
	CorsOrigin     = "Access-Control-Allow-Origin"
	CorsHeaders    = "Access-Control-Allow-Headers"
	CorsMethods    = "Access-Control-Allow-Methods"

	// Headers values
	ApplicationJson = "application/json"
	Authorization   = "Authorization"

	// CORS value
	ValueCorsOrigin = "CORS_ORIGIN"

	// Token secret and expiry
	ClientSecret              = "CLIENT_SECRET"
	TokenExpireMinutes        = "TOKEN_EXPIRE_MINUTES"
	RefreshClientSecret       = "REFRESH_CLIENT_SECRET"
	RefreshTokenExpireMinutes = "REFRESH_TOKEN_EXPIRE_MINUTES"
)

// Type used for intercepting http requests.
type MiddlewareInterceptor func(http.ResponseWriter, *http.Request, http.HandlerFunc)

// Type used for handling function after intercepting http request.
type MiddlewareHandlerFunc http.HandlerFunc

// Type used for the Middleware chain as an array of MiddlewareInterceptor.
type MiddlewareChain []MiddlewareInterceptor

// Adds an array of interceptors to the MiddlewareInterceptor chain.
func (mwc MiddlewareChain) Add(interceptor ...MiddlewareInterceptor) MiddlewareChain {
	return append(mwc, interceptor...)
}

// Method called after intercepting http request.
func (continuation MiddlewareHandlerFunc) Intercept(mw MiddlewareInterceptor) MiddlewareHandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		mw(writer, request, http.HandlerFunc(continuation))
	}
}

// Method used for attaching the MiddlewareChain for interception of http request.
func (chain MiddlewareChain) Handler(handler http.HandlerFunc) http.HandlerFunc {
	curr := MiddlewareHandlerFunc(handler)
	for i := len(chain) - 1; i >= 0; i-- {
		mw := chain[i]
		curr = curr.Intercept(mw)
	}
	return http.HandlerFunc(curr)
}

// Interceptor which adds CORS related headers.
func CorsInterceptor(methods string) MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Set(CorsOrigin, os.Getenv(ValueCorsOrigin))
		w.Header().Set(CorsMethods, methods)
		w.Header().Add(CorsHeaders, Authorization)
		next(w, r)
	}
}

// Interceptor which sets the content type as application/json.
func ApplicationJsonInterceptor() MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		w.Header().Set(ContentTypeKey, ApplicationJson)
		next(w, r)
	}
}

// Interceptor which checks if the header has the correct accessToken.
func AuthenticationInterceptor() MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		secret := os.Getenv(ClientSecret)
		_, err := Authenticate(r, secret)
		if r.Method != http.MethodOptions && err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// Interceptor which checks if the header has the correct refreshToken.
func RefreshAuthenticationInterceptor() MiddlewareInterceptor {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		secret := os.Getenv(RefreshClientSecret)
		_, err := Authenticate(r, secret)
		if r.Method != http.MethodOptions && err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// Creates the access token for the username.
func CreateAccessToken(claims jwt.MapClaims) (string, error) {
	return CreateToken(claims, os.Getenv(ClientSecret), os.Getenv(TokenExpireMinutes))
}

// Creates the refresh token for the username.
func CreateRefreshToken(claims jwt.MapClaims) (string, error) {
	return CreateToken(claims, os.Getenv(RefreshClientSecret), os.Getenv(RefreshTokenExpireMinutes))
}

// Creates the jwt token for the given parameters.
func CreateToken(claims jwt.MapClaims, secret string, expires string) (string, error) {
	expiry, err := strconv.Atoi(expires)
	if err != nil {
		return "", err
	}
	expireTime := time.Minute * time.Duration(expiry)
	claims["expires"] = time.Now().Add(expireTime).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

// Authenticates the access token present in the request headers.
func AuthenticateAccessToken(r *http.Request) (jwt.Claims, error) {
	return Authenticate(r, os.Getenv(ClientSecret))
}

// Authenticates the refresh token present in the request headers.
func AuthenticateRefreshToken(r *http.Request) (jwt.Claims, error) {
	return Authenticate(r, os.Getenv(RefreshClientSecret))
}

// Authenticates the jwt token with the given secret.
func Authenticate(r *http.Request, secret string) (jwt.Claims, error) {
	bearerToken := r.Header.Get(Authorization)
	split := strings.Split(bearerToken, " ")
	if len(split) == 2 {
		tokenString := split[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return token.Claims, nil
		})
		return token.Claims, err
	}
	return nil, fmt.Errorf("token not available")
}
