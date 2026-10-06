package sanitize

import "testing"

func TestCheckURL(t *testing.T) {
	cases := []struct {
		in            string
		allowRelative bool
		wantOK        bool
	}{
		{"https://example.com/x", true, true},
		{"http://example.com", true, true},
		{"HTTPS://EXAMPLE.COM", true, true},
		{"mailto:a@b.c", true, true},
		{"javascript:alert(1)", true, false},
		{"JaVaScRiPt:alert(1)", true, false},
		{"java\tscript:alert(1)", true, false}, // 控制字符绕过
		{"  javascript:alert(1)  ", true, false},
		{"data:text/html,<script>", true, false},
		{"vbscript:msgbox(1)", true, false},
		{"file:///etc/passwd", true, false},
		{"//evil.com/x", true, false}, // 协议相对地址拒绝
		{"/relative/path", true, true},
		{"page.html#frag", true, true},
		{"?query=1", true, true},
		{"/relative/path", false, false}, // 相对地址可配置拒绝
		{"", true, false},
		{":bad", true, false},
	}
	for _, c := range cases {
		_, ok := CheckURL(c.in, c.allowRelative)
		if ok != c.wantOK {
			t.Errorf("CheckURL(%q, %v) ok=%v, want %v", c.in, c.allowRelative, ok, c.wantOK)
		}
	}
}

func TestCheckURLDeterministic(t *testing.T) {
	a, ok1 := CheckURL("https://example.com", true)
	for i := 0; i < 100; i++ {
		b, ok2 := CheckURL("https://example.com", true)
		if a != b || ok1 != ok2 {
			t.Fatal("CheckURL not deterministic")
		}
	}
}
