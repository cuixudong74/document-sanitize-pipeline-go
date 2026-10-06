package sanitize

import (
	"strings"
	"testing"
)

func sanitizeString(t *testing.T, p *Policy, input string) string {
	t.Helper()
	res, err := Parse(strings.NewReader(input), 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return RenderString(p.Sanitize(res.Doc))
}

func TestScriptStripped(t *testing.T) {
	out := sanitizeString(t, DefaultPolicy(), `<p>hi</p><script>alert(1)</script>`)
	if strings.Contains(out, "script") || strings.Contains(out, "alert") {
		t.Fatalf("script not stripped: %q", out)
	}
	if !strings.Contains(out, "<p>hi</p>") {
		t.Fatalf("safe content lost: %q", out)
	}
}

func TestEventHandlerAttrsStripped(t *testing.T) {
	out := sanitizeString(t, DefaultPolicy(), `<p onclick="x()" onmouseover="y()">t</p>`)
	if strings.Contains(out, "on") {
		t.Fatalf("event handlers survived: %q", out)
	}
}

func TestUnknownElementUnwrapped(t *testing.T) {
	out := sanitizeString(t, DefaultPolicy(), `<marquee><p>keep</p></marquee>`)
	if strings.Contains(out, "marquee") {
		t.Fatalf("unknown element kept: %q", out)
	}
	if !strings.Contains(out, "<p>keep</p>") {
		t.Fatalf("children of unknown element lost: %q", out)
	}
}

func TestAttributeAllowedPerElement(t *testing.T) {
	p := DefaultPolicy()
	// href 在 <a> 上放行，在 <div> 上必须剥离（同名属性不一刀切）
	out := sanitizeString(t, p, `<a href="https://ok">x</a><div href="https://no">y</div>`)
	if !strings.Contains(out, `<a href="https://ok">`) {
		t.Fatalf("a[href] dropped: %q", out)
	}
	if strings.Contains(out, `<div href`) {
		t.Fatalf("div[href] kept: %q", out)
	}
}

func TestImgSrcJavascriptStripped(t *testing.T) {
	out := sanitizeString(t, DefaultPolicy(), `<img src="javascript:alert(1)" alt="x">`)
	if strings.Contains(out, "javascript") {
		t.Fatalf("javascript: src survived: %q", out)
	}
	if !strings.Contains(out, `alt="x"`) {
		t.Fatalf("safe attr lost: %q", out)
	}
}

func TestStyleTagDroppedWithContent(t *testing.T) {
	out := sanitizeString(t, DefaultPolicy(), `<style>body{display:none}</style><p>v</p>`)
	if strings.Contains(out, "display") {
		t.Fatalf("style content leaked: %q", out)
	}
}

func TestCommentStripped(t *testing.T) {
	out := sanitizeString(t, DefaultPolicy(), `<p>a<!--[if IE]><script>x</script><![endif]-->b</p>`)
	if strings.Contains(out, "script") || strings.Contains(out, "if IE") {
		t.Fatalf("comment content leaked: %q", out)
	}
}

func TestDeterministicOutput(t *testing.T) {
	input := `<div class="a b" id="x" style="color: red; font-size: 12px"><a href="https://e.com">l</a></div>`
	first := sanitizeString(t, DefaultPolicy(), input)
	for i := 0; i < 20; i++ {
		if got := sanitizeString(t, DefaultPolicy(), input); got != first {
			t.Fatalf("run %d differs: %q vs %q", i, got, first)
		}
	}
}
