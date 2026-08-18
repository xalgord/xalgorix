package web

import "testing"

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:6060":             true,
		"localhost:6060":             true,
		"[::1]:6060":                 true,
		":6060":                      true,
		"127.5.0.1:6060":             true,
		"0.0.0.0:6060":               false,
		"192.168.1.10:6060":          false,
		"scanner2.xalgorix.com:6060": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
