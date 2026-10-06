package sanitize

import (
	"strings"
	"testing"
)

// 批量导入：单篇失败不影响其他文档，失败原因可区分。
func TestBatchFailureIsolation(t *testing.T) {
	s := NewStore()
	out := s.ImportBatch([]BatchItem{
		{Key: "good", Input: []byte(`<p>ok</p>`)},
		{Key: "policy-reject", Input: []byte(`<script>alert(1)</script>`)},
		{Key: "too-large", Input: []byte(strings.Repeat("x", 1000))},
		{Key: "also-good", Input: []byte(`<b>fine</b>`)},
	}, PolicyV1, Limits{MaxBytes: 100})

	if len(out.Succeeded) != 2 {
		t.Fatalf("want 2 successes, got %d", len(out.Succeeded))
	}
	if out.Succeeded["good"] == nil || out.Succeeded["also-good"] == nil {
		t.Fatal("good docs should succeed")
	}
	if len(out.Failed) != 2 {
		t.Fatalf("want 2 failures, got %d", len(out.Failed))
	}
	if out.Failed["policy-reject"].Kind != ErrKindPolicy {
		t.Fatalf("policy-reject kind = %v", out.Failed["policy-reject"].Kind)
	}
	if out.Failed["too-large"].Kind != ErrKindTooLarge {
		t.Fatalf("too-large kind = %v", out.Failed["too-large"].Kind)
	}
	// 失败与成功结果均可查询。
	if _, ok := s.Get(out.Succeeded["good"].ID); !ok {
		t.Fatal("succeeded doc should be queryable")
	}
}

// 批量重复导入幂等。
func TestBatchIdempotent(t *testing.T) {
	s := NewStore()
	items := []BatchItem{{Key: "a", Input: []byte(`<p>same</p>`)}}
	out1 := s.ImportBatch(items, PolicyV1, Limits{})
	out2 := s.ImportBatch(items, PolicyV1, Limits{})
	if out1.Succeeded["a"].ID != out2.Succeeded["a"].ID {
		t.Fatal("batch re-import should be idempotent")
	}
	if s.Len() != 1 {
		t.Fatalf("want 1 doc, got %d", s.Len())
	}
}
