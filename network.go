package net

import (
	"net/url"
	"strconv"
)

// Extracts an int parameter from the values of query params.
func ParamInt(values url.Values, key string, def int) int {
	value := def
	if values.Get(key) != "" {
		value, _ = strconv.Atoi(values.Get(key))
	}
	return value
}

// Extracts a string parameter from the values of query params.
func ParamString(values url.Values, key string, def string) string {
	value := def
	if values.Get(key) != "" {
		value = values.Get(key)
	}
	return value
}
