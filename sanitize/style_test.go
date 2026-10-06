package sanitize

import (
	"strings"
	"testing"
)

func testAllowedStyles() map[string]bool {
	return set("color", "font-size")
}

func TestStyleFiltersDisallowedProps(t *testing.T) {
	out := SanitizeStyle("color: red; position: fixed; font-size: 12px", testAllowedStyles())
	if strings.Contains(out, "position") {
		t.Fatalf("disallowed prop kept: %q", out)
	}
	if !strings.Contains(out, "color: red") || !strings.Contains(out, "font-size: 12px") {
		t.Fatalf("allowed props lost: %q", out)
	}
}

func TestStyleRejectsDangerousValues(t *testing.T) {
	for _, css := range []string{
		"color: expression(alert(1))",
		"color: url(javascript:alert(1))",
		"color: url(data:text/html,x)",
		"color: -moz-binding",
	} {
		if out := SanitizeStyle(css, set("color", "background")); out != "" {
			t.Fatalf("dangerous style survived: %q -> %q", css, out)
		}
	}
	// 危险声明被丢弃，安全声明保留
	out := SanitizeStyle("color: red; background: url(//evil/x)", set("color", "background"))
	if out != "color: red; " {
		t.Fatalf("got %q", out)
	}
}

func TestStyleToleratesMalformedDecls(t *testing.T) {
	out := SanitizeStyle("color: red; broken; : nope; font-size: 12px;", testAllowedStyles())
	if !strings.Contains(out, "color: red") || !strings.Contains(out, "font-size: 12px") {
		t.Fatalf("good decls lost: %q", out)
	}
}

func TestStyleDeterministicAndSorted(t *testing.T) {
	a := SanitizeStyle("font-size: 12px; color: red", testAllowedStyles())
	b := SanitizeStyle("color: red; font-size: 12px", testAllowedStyles())
	if a != b {
		t.Fatalf("order-dependent output: %q vs %q", a, b)
	}
	if a != "color: red; font-size: 12px; " {
		t.Fatalf("unexpected canonical form: %q", a)
	}
}

func TestRewriteIdentStable(t *testing.T) {
	a := RewriteIdent("v1", "my-class")
	b := RewriteIdent("v1", "my-class")
	if a != b {
		t.Fatal("rewrite not stable")
	}
	if !strings.HasPrefix(a, "dz-") {
		t.Fatalf("missing prefix: %q", a)
	}
	if RewriteIdent("v1", "x") == RewriteIdent("v2", "x") {
		t.Fatal("different scopes must not collide")
	}
	if RewriteIdent("v1", "a") == RewriteIdent("v1", "b") {
		t.Fatal("different names must not collide")
	}
}

func TestClassAndIdRewrittenInOutput(t *testing.T) {
	out := sanitizeString(t, DefaultPolicy(), `<p class="intro big" id="top">x</p>`)
	if strings.Contains(out, "intro") || strings.Contains(out, `"top"`) {
		t.Fatalf("original idents leaked: %q", out)
	}
	if !strings.Contains(out, "dz-") {
		t.Fatalf("rewritten idents missing: %q", out)
	}
	// 同一输入重写结果一致
	out2 := sanitizeString(t, DefaultPolicy(), `<p class="intro big" id="top">x</p>`)
	if out != out2 {
		t.Fatalf("rewrite not deterministic: %q vs %q", out, out2)
	}
}
