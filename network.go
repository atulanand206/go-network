package net

import (
	"net/url"
	"strconv"
)

func ParamInt(values url.Values, key string, def int) int {
	value := def
	if values.Get(key) != "" {
		value, _ = strconv.Atoi(values.Get(key))
	}
	return value
}

func ParamString(values url.Values, key string, def string) string {
	value := def
	if values.Get(key) != "" {
		value = values.Get(key)
	}
	return value
}
