package sanitize

import (
	"strings"
	"testing"
)

func mustSanitize(t *testing.T, input, version string) *Result {
	t.Helper()
	res, err := Sanitize([]byte(input), version, Limits{})
	if err != nil {
		t.Fatalf("Sanitize(%q) failed: %v", input, err)
	}
	return res
}

func TestSanitizeBasic(t *testing.T) {
	res := mustSanitize(t, `<p>hello <b>world</b></p>`, PolicyV1)
	if res.HTML != `<p>hello <b>world</b></p>` {
		t.Fatalf("HTML = %q", res.HTML)
	}
	if res.PolicyVersion != PolicyV1 {
		t.Fatalf("version = %q", res.PolicyVersion)
	}
}

func TestSanitizeStripsScript(t *testing.T) {
	res := mustSanitize(t, `<p>safe</p><script>alert(1)</script>`, PolicyV1)
	if strings.Contains(res.HTML, "script") || strings.Contains(res.HTML, "alert") {
		t.Fatalf("script not stripped: %q", res.HTML)
	}
	found := false
	for _, is := range res.Issues {
		if is.Kind == IssueStrippedElement {
			found = true
		}
	}
	if !found {
		t.Fatal("want stripped-element issue")
	}
}

func TestSanitizeStripsEventHandlers(t *testing.T) {
	res := mustSanitize(t, `<p onclick="alert(1)" onmouseover="x()">hi</p>`, PolicyV1)
	if strings.Contains(res.HTML, "onclick") || strings.Contains(res.HTML, "onmouseover") {
		t.Fatalf("event handlers not stripped: %q", res.HTML)
	}
	if res.HTML != `<p>hi</p>` {
		t.Fatalf("HTML = %q", res.HTML)
	}
}

func TestSanitizeUnknownElementUnwrapped(t *testing.T) {
	res := mustSanitize(t, `<marquee><p>keep me</p></marquee>`, PolicyV1)
	if res.HTML != `<p>keep me</p>` {
		t.Fatalf("HTML = %q", res.HTML)
	}
}

func TestSanitizeIframeDroppedWithContent(t *testing.T) {
	res := mustSanitize(t, `<p>a</p><iframe src="https://evil">fallback</iframe><p>b</p>`, PolicyV1)
	if strings.Contains(res.HTML, "iframe") || strings.Contains(res.HTML, "fallback") {
		t.Fatalf("iframe subtree not dropped: %q", res.HTML)
	}
}

// 白名单绕过：同名属性在不同元素上区别对待。
func TestSanitizeAttrPerElement(t *testing.T) {
	res := mustSanitize(t,
		`<a href="https://ok" target="_blank">x</a><img src="https://img" href="https://bad">`,
		PolicyV1)
	if !strings.Contains(res.HTML, `href="https://ok"`) {
		t.Fatalf("a[href] should be kept: %q", res.HTML)
	}
	if strings.Contains(res.HTML, "target") {
		t.Fatalf("a[target] should be stripped: %q", res.HTML)
	}
	if strings.Contains(res.HTML, `<img`) && strings.Contains(res.HTML[strings.Index(res.HTML, "<img"):], "href") {
		t.Fatalf("img[href] should be stripped: %q", res.HTML)
	}
}

// 协议绕过：javascript: 及其变形必须被清除。
func TestSanitizeProtocolBypass(t *testing.T) {
	cases := []string{
		`<a href="javascript:alert(1)">x</a>`,
		`<a href="JaVaScRiPt:alert(1)">x</a>`,
		`<a href="java&#9;script:alert(1)">x</a>`,
		`<a href="javascript&#58;alert(1)">x</a>`,
		`<a href="  javascript:alert(1)">x</a>`,
		`<a href="vbscript:msgbox(1)">x</a>`,
		`<a href="data:text/html,<script>alert(1)</script>">x</a>`,
	}
	for _, in := range cases {
		res := mustSanitize(t, in, PolicyV1)
		if strings.Contains(res.HTML, "href") {
			t.Fatalf("unsafe href kept for %q: %q", in, res.HTML)
		}
	}
}

func TestSanitizeSafeURLsKept(t *testing.T) {
	res := mustSanitize(t,
		`<a href="https://example.com/x?a=1&amp;b=2">abs</a>`+
			`<a href="/relative/path">rel</a>`+
			`<a href="//cdn.example.com/p">proto-rel</a>`+
			`<a href="mailto:a@b.c">mail</a>`,
		PolicyV1)
	for _, want := range []string{
		`href="https://example.com/x?a=1&amp;b=2"`,
		`href="/relative/path"`,
		`href="//cdn.example.com/p"`,
		`href="mailto:a@b.c"`,
	} {
		if !strings.Contains(res.HTML, want) {
			t.Fatalf("want %q in %q", want, res.HTML)
		}
	}
}

// 相对地址在策略关闭时必须被清除。
func TestSanitizeRelativeURLPolicy(t *testing.T) {
	p := builtinV1()
	p.Version = "test-no-relative"
	p.AllowRelativeURL = false
	RegisterPolicy(p)
	res := mustSanitize(t, `<a href="/rel">x</a><a href="https://ok">y</a>`, "test-no-relative")
	if strings.Contains(res.HTML, "/rel") {
		t.Fatalf("relative URL should be dropped: %q", res.HTML)
	}
	if !strings.Contains(res.HTML, `href="https://ok"`) {
		t.Fatalf("absolute https URL should be kept: %q", res.HTML)
	}
}

// 样式注入：危险声明剥离，安全声明保留且输出确定。
func TestSanitizeStyle(t *testing.T) {
	res := mustSanitize(t,
		`<p style="color: red; width: expression(alert(1)); background-color: url(javascript:x); font-size: 12px">hi</p>`,
		PolicyV2)
	if !strings.Contains(res.HTML, "color: red") {
		t.Fatalf("safe style dropped: %q", res.HTML)
	}
	if !strings.Contains(res.HTML, "font-size: 12px") {
		t.Fatalf("safe style dropped: %q", res.HTML)
	}
	if strings.Contains(res.HTML, "expression") || strings.Contains(res.HTML, "javascript") {
		t.Fatalf("dangerous style kept: %q", res.HTML)
	}
}

// v1 不允许 style 属性，必须整体剥离。
func TestSanitizeStyleNotAllowedInV1(t *testing.T) {
	res := mustSanitize(t, `<p style="color: red">hi</p>`, PolicyV1)
	if strings.Contains(res.HTML, "style") {
		t.Fatalf("style should be stripped in v1: %q", res.HTML)
	}
}

// 类名与 id 按稳定规则重写。
func TestSanitizeClassRewrite(t *testing.T) {
	res := mustSanitize(t, `<p class="foo bar-baz" id="main">hi</p>`, PolicyV2)
	if !strings.Contains(res.HTML, `class="doc-foo doc-bar-baz"`) {
		t.Fatalf("class not rewritten: %q", res.HTML)
	}
	if !strings.Contains(res.HTML, `id="doc-main"`) {
		t.Fatalf("id not rewritten: %q", res.HTML)
	}
}

// 幂等性：同一输入多次净化结果完全一致。
func TestSanitizeDeterministic(t *testing.T) {
	input := `<div><p style="font-size:12px;color:red" class="a b">x</p><img src="https://i/x.png" alt="a"></div>`
	first := mustSanitize(t, input, PolicyV2)
	for i := 0; i < 10; i++ {
		got := mustSanitize(t, input, PolicyV2)
		if got.HTML != first.HTML {
			t.Fatalf("run %d differs:\n%s\n%s", i, got.HTML, first.HTML)
		}
	}
}

// 畸形输入不失败且输出安全。
func TestSanitizeMalformed(t *testing.T) {
	res := mustSanitize(t, `<div><p>unclosed<b>bold</div></b></p><p <p>`, PolicyV1)
	if !strings.Contains(res.HTML, "unclosed") {
		t.Fatalf("content lost: %q", res.HTML)
	}
	if strings.Contains(res.HTML, "</b></p>") && !strings.Contains(res.HTML, "<b>") {
		t.Fatalf("stray tags leaked: %q", res.HTML)
	}
}

// 纯危险内容被策略拒绝，错误类别可区分。
func TestSanitizePolicyRejectsEmptyResult(t *testing.T) {
	_, err := Sanitize([]byte(`<script>alert(1)</script>`), PolicyV1, Limits{})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindPolicy {
		t.Fatalf("want policy error, got %v", err)
	}
}

func TestSanitizeUnknownPolicy(t *testing.T) {
	_, err := Sanitize([]byte(`<p>x</p>`), "v999", Limits{})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindPolicy {
		t.Fatalf("want policy error, got %v", err)
	}
}

func TestSanitizeTooLarge(t *testing.T) {
	_, err := Sanitize([]byte(strings.Repeat("<p>x</p>", 100)), PolicyV1, Limits{MaxBytes: 50})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindTooLarge {
		t.Fatalf("want too-large error, got %v", err)
	}
}

// 文本中的 HTML 特殊字符必须被转义。
func TestSanitizeEscapesText(t *testing.T) {
	res := mustSanitize(t, `<p>1 < 2 & "quotes"</p>`, PolicyV1)
	if !strings.Contains(res.HTML, "1 &lt; 2 &amp;") {
		t.Fatalf("text not escaped: %q", res.HTML)
	}
}
