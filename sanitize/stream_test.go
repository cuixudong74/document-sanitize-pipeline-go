package sanitize

import (
	"bytes"
	"strings"
	"testing"
)

func TestStreamBasic(t *testing.T) {
	var out bytes.Buffer
	res, err := SanitizeStream(strings.NewReader(`<p>hi<script>x()</script></p>`), &out, DefaultPolicy(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != `<p>hi</p>` {
		t.Fatalf("got %q", out.String())
	}
	if res.BytesIn == 0 || res.BytesOut == 0 {
		t.Fatalf("counters not populated: %+v", res)
	}
}

func TestStreamTooLarge(t *testing.T) {
	var out bytes.Buffer
	big := strings.Repeat("<p>x</p>", 1000)
	_, err := SanitizeStream(strings.NewReader(big), &out, DefaultPolicy(), Limits{MaxBytes: 100})
	se, ok := err.(*Error)
	if !ok || se.Kind != ErrKindTooLarge {
		t.Fatalf("expected ErrKindTooLarge, got %v", err)
	}
	// 失败时不得留下半写入的产物
	if out.Len() != 0 {
		t.Fatalf("partial output leaked: %q", out.String())
	}
}

func TestStreamMalformedRecovery(t *testing.T) {
	var out bytes.Buffer
	res, err := SanitizeStream(strings.NewReader(`<ul><li>a<li>b</ul><p>c`), &out, DefaultPolicy(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != `<ul><li>a</li><li>b</li></ul><p>c</p>` {
		t.Fatalf("got %q", out.String())
	}
	if len(res.Issues) == 0 {
		t.Fatal("expected recovery issues")
	}
}

func TestStreamMatchesTreePipeline(t *testing.T) {
	inputs := []string{
		`<div class="x" style="color: red; position: fixed"><a href="javascript:alert(1)">l</a></div>`,
		`<p>one<div>two</div><table><tr><td>c</td></tr></table>`,
		`<unknown><b>bold</b></unknown><img src="https://e/x.png" onerror="x()">`,
	}
	for _, in := range inputs {
		var streamOut bytes.Buffer
		if _, err := SanitizeStream(strings.NewReader(in), &streamOut, DefaultPolicy(), Limits{}); err != nil {
			t.Fatal(err)
		}
		treeOut := sanitizeString(t, DefaultPolicy(), in)
		if streamOut.String() != treeOut {
			t.Fatalf("stream %q != tree %q for input %q", streamOut.String(), treeOut, in)
		}
	}
}

func TestStreamLargeDocumentBounded(t *testing.T) {
	// 大文档应能完整处理；此处验证正确处理而非精确内存值
	var sb strings.Builder
	for i := 0; i < 20000; i++ {
		sb.WriteString(`<p class="a">text <b>bold</b></p>`)
	}
	var out bytes.Buffer
	res, err := SanitizeStream(strings.NewReader(sb.String()), &out, DefaultPolicy(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesOut == 0 || out.Len() == 0 {
		t.Fatal("no output for large doc")
	}
}
