package terminal

import "testing"

func TestCapDirbusterRuntime(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "ffuf without maxtime gets capped",
			in:   "ffuf -u http://t/FUZZ -w wl.txt -mc 200",
			want: "ffuf -u http://t/FUZZ -w wl.txt -mc 200 -maxtime 180",
		},
		{
			name: "ffuf piped to head caps the ffuf stage only",
			in:   "ffuf -u http://t/FUZZ -w wl.txt | head -60",
			want: "ffuf -u http://t/FUZZ -w wl.txt -maxtime 180 | head -60",
		},
		{
			name: "ffuf with explicit maxtime is preserved",
			in:   "ffuf -u http://t/FUZZ -w wl.txt -maxtime 30",
			want: "ffuf -u http://t/FUZZ -w wl.txt -maxtime 30",
		},
		{
			name: "feroxbuster without time-limit gets capped",
			in:   "feroxbuster -u http://t -w wl.txt -x php",
			want: "feroxbuster -u http://t -w wl.txt -x php --time-limit 180s",
		},
		{
			name: "feroxbuster with time-limit preserved",
			in:   "feroxbuster -u http://t --time-limit 60s",
			want: "feroxbuster -u http://t --time-limit 60s",
		},
		{
			name: "dirsearch without max-time gets capped",
			in:   "dirsearch -u http://t -w wl.txt",
			want: "dirsearch -u http://t -w wl.txt --max-time 180",
		},
		{
			name: "non-dirbuster command untouched",
			in:   "curl -sk http://t/login",
			want: "curl -sk http://t/login",
		},
		{
			name: "sqlmap is not capped",
			in:   "sqlmap -u http://t --batch --dump",
			want: "sqlmap -u http://t --batch --dump",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CapDirbusterRuntime(tc.in); got != tc.want {
				t.Errorf("CapDirbusterRuntime(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
		})
	}
}
