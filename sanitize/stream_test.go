package sanitize

import (
	"io"
	"strings"
	"testing"
)

// 流式解析：正常输入完整处理。
func TestParseReaderOK(t *testing.T) {
	r := strings.NewReader(`<p>stream <b>ok</b></p>`)
	res, err := ParseReader(r, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Doc.Children) != 1 || res.Doc.Children[0].Tag != "p" {
		t.Fatalf("unexpected tree: %+v", res.Doc.Children)
	}
}

// 流式解析：超限立即失败，错误类别为 too-large，且不产出半成品。
func TestParseReaderLimitImmediate(t *testing.T) {
	// 用一个无限 reader 验证限流确实在读取层生效。
	r := &infiniteReader{}
	_, err := ParseReader(r, Limits{MaxBytes: 1024})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindTooLarge {
		t.Fatalf("want too-large, got %v", err)
	}
}

type infiniteReader struct{}

func (r *infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// 深度超限：可区分错误。
func TestParseDepthLimit(t *testing.T) {
	input := strings.Repeat("<div>", 100) + "x" + strings.Repeat("</div>", 100)
	_, err := Parse([]byte(input), Limits{MaxDepth: 10})
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindTooLarge {
		t.Fatalf("want too-large, got %v", err)
	}
}

// 恰好等于上限的输入应正常处理。
func TestParseReaderExactLimit(t *testing.T) {
	input := strings.Repeat("x", 512)
	res, err := ParseReader(strings.NewReader(input), Limits{MaxBytes: 512})
	if err != nil {
		t.Fatalf("exact-limit input should succeed: %v", err)
	}
	if len(res.Doc.Children) != 1 {
		t.Fatal("want one text node")
	}
}

// 中断后不留半写入产物：SanitizeReader 失败时返回的 Result 为 nil。
func TestSanitizeReaderNoPartialOutput(t *testing.T) {
	r := io.MultiReader(strings.NewReader("<p>ok</p>"), &infiniteReader{})
	res, err := SanitizeReader(r, PolicyV1, Limits{MaxBytes: 64})
	if res != nil {
		t.Fatal("no partial result should be returned on failure")
	}
	e, ok := err.(*Error)
	if !ok || e.Kind != ErrKindTooLarge {
		t.Fatalf("want too-large, got %v", err)
	}
}
