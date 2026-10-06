package sanitize

import (
	"strings"
	"testing"
)

func tagsOf(n *Node) []string {
	var out []string
	var walk func(*Node)
	walk = func(x *Node) {
		if x.Kind == KindElement {
			out = append(out, x.Tag)
		}
		for _, c := range x.Children {
			walk(c)
		}
	}
	walk(n)
	return out
}

func TestParseWellFormed(t *testing.T) {
	res, err := Parse([]byte(`<p>hello <b>world</b></p>`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Issues) != 0 {
		t.Fatalf("unexpected issues: %+v", res.Issues)
	}
	got := strings.Join(tagsOf(res.Doc), ",")
	if got != "p,b" {
		t.Fatalf("tags = %q", got)
	}
}

func TestParseUnclosedTag(t *testing.T) {
	res, err := Parse([]byte(`<div><p>text`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(tagsOf(res.Doc), ",")
	if got != "div,p" {
		t.Fatalf("tags = %q", got)
	}
	var unclosed int
	for _, is := range res.Issues {
		if is.Kind == IssueUnclosedTag {
			unclosed++
		}
	}
	if unclosed != 2 {
		t.Fatalf("want 2 unclosed issues, got %d: %+v", unclosed, res.Issues)
	}
}

func TestParseStrayEndTag(t *testing.T) {
	res, err := Parse([]byte(`<p>a</p></b>`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range res.Issues {
		if is.Kind == IssueStrayEndTag {
			found = true
		}
	}
	if !found {
		t.Fatalf("want stray-end-tag issue, got %+v", res.Issues)
	}
}

func TestParseIllegalNestingP(t *testing.T) {
	res, err := Parse([]byte(`<p>one<p>two`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// 两个 p 应为兄弟而非嵌套。
	if len(res.Doc.Children) != 2 {
		t.Fatalf("want 2 top-level children, got %d", len(res.Doc.Children))
	}
	found := false
	for _, is := range res.Issues {
		if is.Kind == IssueIllegalNesting {
			found = true
		}
	}
	if !found {
		t.Fatalf("want illegal-nesting issue, got %+v", res.Issues)
	}
}

func TestParseMalformedTagAsText(t *testing.T) {
	res, err := Parse([]byte(`a < b and <3 and <div`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// 全部恢复为文本，不失败。
	if len(res.Doc.Children) == 0 {
		t.Fatal("want text children")
	}
	var texts []string
	for _, c := range res.Doc.Children {
		if c.Kind == KindText {
			texts = append(texts, c.Data)
		}
	}
	joined := strings.Join(texts, "")
	if !strings.Contains(joined, "a < b") || !strings.Contains(joined, "<div") {
		t.Fatalf("unexpected text: %q", joined)
	}
}

func TestParseIssuePosition(t *testing.T) {
	res, err := Parse([]byte("line1\n<p>ok</p></b>"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var stray *Issue
	for i := range res.Issues {
		if res.Issues[i].Kind == IssueStrayEndTag {
			stray = &res.Issues[i]
		}
	}
	if stray == nil {
		t.Fatal("want stray issue")
	}
	if stray.Line != 2 || stray.Offset != 15 {
		t.Fatalf("bad position: %+v", stray)
	}
}

func TestParseScriptRawText(t *testing.T) {
	res, err := Parse([]byte(`<script>if (a<b) { x("</p>"); }</script><p>after</p>`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// script 内容中的 "<b" 与 "</p>" 不得影响树结构。
	got := strings.Join(tagsOf(res.Doc), ",")
	if got != "script,p" {
		t.Fatalf("tags = %q", got)
	}
}

func TestParseTooLargeBytes(t *testing.T) {
	_, err := Parse([]byte(strings.Repeat("x", 100)), Limits{MaxBytes: 10})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindTooLarge {
		t.Fatalf("want ErrKindTooLarge, got %v", err)
	}
}

func TestParseTooLargeNodes(t *testing.T) {
	input := strings.Repeat("<br>", 50)
	_, err := Parse([]byte(input), Limits{MaxNodes: 10})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindTooLarge {
		t.Fatalf("want ErrKindTooLarge, got %v", err)
	}
}

func TestParseReaderLimit(t *testing.T) {
	r := strings.NewReader(strings.Repeat("x", 1000))
	_, err := ParseReader(r, Limits{MaxBytes: 100})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindTooLarge {
		t.Fatalf("want ErrKindTooLarge, got %v", err)
	}
}
