package httpclient

import (
	"reflect"
	"testing"
)

func TestParseAuthHeaders(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"empty", "   ", nil},
		{
			"semicolon separated",
			"Cookie: session=abc; Authorization: Bearer xyz",
			map[string]string{"Cookie": "session=abc", "Authorization": "Bearer xyz"},
		},
		{
			"newline separated",
			"Cookie: a=1\nX-Api-Key: k",
			map[string]string{"Cookie": "a=1", "X-Api-Key": "k"},
		},
		{
			"bare token becomes Authorization",
			"my-raw-token",
			map[string]string{"Authorization": "my-raw-token"},
		},
		{
			"cookie value containing equals is preserved",
			"Cookie: sid=a=b=c",
			map[string]string{"Cookie": "sid=a=b=c"},
		},
		{
			"bare 'Bearer' alone is ignored",
			"Bearer",
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseAuthHeaders(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseAuthHeaders(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseAuthHeaders_MultiCookiePreserved(t *testing.T) {
	// A browser-copied multi-cookie header must stay intact (not split on ';').
	got := ParseAuthHeaders("Cookie: a=1; b=2; c=3")
	if got["Cookie"] != "a=1; b=2; c=3" {
		t.Fatalf("multi-cookie corrupted: %v", got)
	}
	if _, ok := got["Authorization"]; ok {
		t.Fatalf("cookie pair mis-parsed as Authorization: %v", got)
	}
}

func TestParseAuthHeaders_CookieThenHeaderOnOneLine(t *testing.T) {
	// A real new header after a cookie value on the same line still splits.
	got := ParseAuthHeaders("Cookie: sid=abc; semi=1; Authorization: Bearer xyz")
	if got["Cookie"] != "sid=abc; semi=1" {
		t.Fatalf("Cookie value = %q, want the two cookie pairs", got["Cookie"])
	}
	if got["Authorization"] != "Bearer xyz" {
		t.Fatalf("Authorization = %q, want 'Bearer xyz'", got["Authorization"])
	}
}

func TestSetAndGetSessionAuth(t *testing.T) {
	const ctx = "scan-ctx-1"
	orig := map[string]string{"Cookie": "s=1", "": "ignored", "X-Api-Key": "k"}
	SetSessionAuth(ctx, orig)

	got := getSessionAuth(ctx)
	if got == nil {
		t.Fatal("expected non-nil auth")
	}
	if got["Cookie"] != "s=1" || got["X-Api-Key"] != "k" {
		t.Fatalf("stored auth = %v", got)
	}
	if _, ok := got[""]; ok {
		t.Fatal("blank header name must be dropped")
	}

	// Returned map must be a copy — mutating it must not affect the store.
	got["Cookie"] = "TAMPERED"
	again := getSessionAuth(ctx)
	if again["Cookie"] != "s=1" {
		t.Fatal("getSessionAuth must return a defensive copy")
	}

	// Mutating the original input after Set must not affect the store either.
	orig["Cookie"] = "MUTATED"
	third := getSessionAuth(ctx)
	if third["Cookie"] != "s=1" {
		t.Fatal("SetSessionAuth must copy the input map")
	}
}

func TestSetSessionAuthClears(t *testing.T) {
	const ctx = "scan-ctx-2"
	SetSessionAuth(ctx, map[string]string{"Cookie": "s=1"})
	if getSessionAuth(ctx) == nil {
		t.Fatal("precondition: auth should be set")
	}
	SetSessionAuth(ctx, nil) // clear
	if getSessionAuth(ctx) != nil {
		t.Fatal("passing empty map must clear the context's auth")
	}
}
