package sanitize

import (
	"strings"
	"testing"
)

func parse(t *testing.T, input string) *ParseResult {
	t.Helper()
	res, err := Parse(strings.NewReader(input), 0)
	if err != nil {
		t.Fatalf("Parse(%q) failed: %v", input, err)
	}
	return res
}

func TestParseWellFormed(t *testing.T) {
	res := parse(t, `<p>hello <b>world</b></p>`)
	if len(res.Issues) != 0 {
		t.Fatalf("unexpected issues: %+v", res.Issues)
	}
	got := RenderString(res.Doc)
	if got != `<p>hello <b>world</b></p>` {
		t.Fatalf("round trip = %q", got)
	}
}

func TestParseUnclosedTag(t *testing.T) {
	res := parse(t, `<div><p>text`)
	if len(res.Issues) == 0 {
		t.Fatal("expected recovery issues for unclosed tags")
	}
	got := RenderString(res.Doc)
	if got != `<div><p>text</p></div>` {
		t.Fatalf("recovered output = %q", got)
	}
	// 问题位置必须能定位到输入
	iss := res.Issues[0]
	if iss.Pos.Start < 0 || iss.Pos.End > len(`<div><p>text`) {
		t.Fatalf("issue position out of range: %+v", iss)
	}
}

func TestParseUnmatchedEndTag(t *testing.T) {
	res := parse(t, `<p>a</span>b</p>`)
	if len(res.Issues) == 0 {
		t.Fatal("expected issue for unmatched end tag")
	}
	got := RenderString(res.Doc)
	if got != `<p>ab</p>` {
		t.Fatalf("output = %q", got)
	}
}

func TestParseIllegalNesting(t *testing.T) {
	// 块级元素嵌进 <p>：应隐式闭合 <p>
	res := parse(t, `<p>one<div>two</div>`)
	got := RenderString(res.Doc)
	if got != `<p>one</p><div>two</div>` {
		t.Fatalf("output = %q", got)
	}
	if len(res.Issues) == 0 {
		t.Fatal("expected implicit-close issue")
	}
}

func TestParseImplicitLiClose(t *testing.T) {
	res := parse(t, `<ul><li>a<li>b</ul>`)
	got := RenderString(res.Doc)
	if got != `<ul><li>a</li><li>b</li></ul>` {
		t.Fatalf("output = %q", got)
	}
}

func TestParseStrayLtAndEntities(t *testing.T) {
	res := parse(t, `a < b &amp; c`)
	got := RenderString(res.Doc)
	if got != `a &lt; b &amp; c` {
		t.Fatalf("output = %q", got)
	}
}

func TestParseUnterminatedTag(t *testing.T) {
	res := parse(t, `<p>ok</p><div`)
	if len(res.Issues) == 0 {
		t.Fatal("expected issue for unterminated tag")
	}
	if !strings.Contains(RenderString(res.Doc), `<p>ok</p>`) {
		t.Fatal("earlier content must survive a trailing malformed tag")
	}
}

func TestParseTooLarge(t *testing.T) {
	_, err := Parse(strings.NewReader(strings.Repeat("x", 100)), 10)
	se, ok := err.(*Error)
	if !ok || se.Kind != ErrKindTooLarge {
		t.Fatalf("expected ErrKindTooLarge, got %v", err)
	}
}

func TestParseIssuePositionsPointIntoInput(t *testing.T) {
	input := `<p>hi</p></b>`
	res := parse(t, input)
	if len(res.Issues) != 1 {
		t.Fatalf("issues = %+v", res.Issues)
	}
	pos := res.Issues[0].Pos
	if got := input[pos.Start:pos.End]; got != "</b>" {
		t.Fatalf("issue span = %q, want </b>", got)
	}
}
