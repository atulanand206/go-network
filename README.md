# go-network

[![Go Reference](https://pkg.go.dev/badge/github.com/atulanand206/go-network.svg)](https://pkg.go.dev/github.com/atulanand206/go-network)

A library exposing an implementation of tools usually required for communicating with RESTFul requests. You can find intercepting and authenticating middlewares as well as methods to authenticate jwt tokens. There are some utility methods for extracting values from request's query parameters as well.

## Learning outcomes
- Create and verify JWT Tokens using a client secret key.
- Build authentication services using access and refresh token using a client secret key and encrypt information in the token for specific purposes.
- Customize middleware interceptor chain to authenticate and scope network requests.
- Restrict network requests using Cross-origin resource sharing policies.

## Installation

The recommended way to get started using the Network driver is by using go modules to install the dependency in your project. This can be done either by importing packages from [go-network](github.com/atulanand206/go-network) and having the build step install the dependency or by explicitly running
```go
go get github.com/atulanand206/go-network
```

## How to implement

- There are a couple of environment variables that you can set for using the jwt token authenticator.
- There are additional methods which accepts the client secrets and expiry times if you'd like to use them directly.

- CLIENT_SECRET : Client secret to be used for creating and authenticating access token.
- TOKEN_EXPIRE_MINUTES : Duration of the validity of access token. The token gets expired after this duration.
- REFRESH_CLIENT_SECRET : Client secret to be used for creating and authenticating refresh token.
- REFRESH_TOKEN_EXPIRE_MINUTES : Duration of the validity of refresh token. The token gets expired after this duration.
    
- The middleware interceptors can be used directly.
- The CORS interceptor expects an environment variable for setting the allowed origin address.

- CORS_ORIGIN : Set this as `*` or the url you'd like to allow the origin to accept the network requests.

- There are examples available for refernce.

## Author

- Atul Anand
