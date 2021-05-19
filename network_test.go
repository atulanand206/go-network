package net_test

import (
	"fmt"
	"net/url"
	"testing"

	net "github.com/atulanand206/go-network"
)

func TestParamInt(t *testing.T) {
	t.Run("it should extract an integer parameter from the url", func(t *testing.T) {
		uri, err := url.Parse("http://search.com?results=1")
		if err != nil {
			t.Fatalf("got error %v while parsing url", err)
		}
		values := uri.Query()
		value := net.ParamInt(values, "results", 0)
		if value != 1 {
			t.Fatalf("expected %d got one %d", 1, value)
		}
	})

	t.Run("it return default for an integer parameter from the url when key is absent", func(t *testing.T) {
		uri, err := url.Parse("http://search.com?results=1")
		if err != nil {
			t.Fatalf("got error %v while parsing url", err)
		}
		values := uri.Query()
		value := net.ParamInt(values, "score", 0)
		if value != 0 {
			t.Fatalf("expected %d got one %d", 1, value)
		}
	})
}

func ExampleParamInt() {
	uri, _ := url.Parse("http://search.com?score=43&rating=93")
	v := uri.Query()
	v.Set("score", "43")
	v.Set("rating", "93")
	fmt.Println(net.ParamInt(v, "score", 3))
	fmt.Println(net.ParamInt(v, "rating", 3))
	fmt.Println(net.ParamInt(v, "wons", 9))
	// Output:
	// 43
	// 93
	// 9
}

func TestParamString(t *testing.T) {
	t.Run("it should extract an string parameter from the url", func(t *testing.T) {
		uri, err := url.Parse("http://search.com?show=Ones")
		if err != nil {
			t.Fatalf("got error %v while parsing url", err)
		}
		values := uri.Query()
		value := net.ParamString(values, "show", "Ones")
		if value != "Ones" {
			t.Fatalf("expected %s, got %s", "Ones", value)
		}
	})

	t.Run("it return default for an string parameter from the url when key is absent", func(t *testing.T) {
		uri, err := url.Parse("http://search.com?show=Ones")
		if err != nil {
			t.Fatalf("got error %v while parsing url", err)
		}
		values := uri.Query()
		value := net.ParamString(values, "winner", "James")
		if value != "James" {
			t.Fatalf("expected %s, got %s", "James", value)
		}
	})
}

func ExampleParamString() {
	uri, _ := url.Parse("http://search.com?name=Ash&friend=Jess")
	v := uri.Query()
	fmt.Println(net.ParamString(v, "name", "Sara"))
	fmt.Println(net.ParamString(v, "friend", "Mark"))
	fmt.Println(net.ParamString(v, "winner", "Jamie"))
	// Output:
	// Ash
	// Jess
	// Jamie
}
