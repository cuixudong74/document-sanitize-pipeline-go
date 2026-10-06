package sanitize

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func newTestStore() *Store {
	return NewStore(DefaultPolicy(), PolicyV2())
}

func TestImportAndGet(t *testing.T) {
	s := newTestStore()
	r := s.Import(context.Background(), "doc1", []byte(`<p>hi</p><script>x</script>`), "v1")
	if r.Status != StatusOK {
		t.Fatalf("import failed: %+v", r.Err)
	}
	rec, ok := s.Get("doc1")
	if !ok {
		t.Fatal("record not found")
	}
	if rec.Content != `<p>hi</p>` || rec.PolicyVersion != "v1" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestImportIdempotent(t *testing.T) {
	s := newTestStore()
	in := []byte(`<p class="a">x</p>`)
	r1 := s.Import(context.Background(), "d", in, "v1")
	r2 := s.Import(context.Background(), "d", in, "v1")
	r3 := s.Import(context.Background(), "d", in, "v1")
	if r1.Status != StatusOK || r2.Status != StatusOK || r3.Status != StatusOK {
		t.Fatal("repeated imports must succeed")
	}
	rec, _ := s.Get("d")
	if rec.Content != `<p class="`+RewriteIdent("v1", "a")+`">x</p>` {
		t.Fatalf("content = %q", rec.Content)
	}
}

func TestImportConcurrentDeterministic(t *testing.T) {
	s := newTestStore()
	in := []byte(`<div class="c" style="color: red"><a href="https://e.com">l</a></div>`)
	const n = 32
	results := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("doc-%d", i%4) // 多 goroutine 竞争同一批 id
			r := s.Import(context.Background(), id, in, "v1")
			if r.Status != StatusOK {
				t.Errorf("import failed: %+v", r.Err)
			}
			rec, _ := s.Get(id)
			results[i] = rec.Content
		}(i)
	}
	wg.Wait()
	for id := 0; id < 4; id++ {
		rec, _ := s.Get(fmt.Sprintf("doc-%d", id))
		for _, got := range results {
			if got != "" && got != rec.Content {
				t.Fatalf("concurrent imports produced divergent content")
			}
		}
	}
}

func TestPolicyVersionCoexistence(t *testing.T) {
	s := newTestStore()
	in := []byte(`<figure><figcaption>cap</figcaption></figure><mark>m</mark>`)
	// v1 不允许 figure/mark，v2 允许
	if r := s.Import(context.Background(), "old", in, "v1"); r.Status != StatusOK {
		t.Fatalf("v1 import failed: %+v", r.Err)
	}
	if r := s.Import(context.Background(), "new", in, "v2"); r.Status != StatusOK {
		t.Fatalf("v2 import failed: %+v", r.Err)
	}
	oldRec, _ := s.Get("old")
	newRec, _ := s.Get("new")
	if strings.Contains(oldRec.Content, "figure") || strings.Contains(oldRec.Content, "mark") {
		t.Fatalf("v1 semantics violated: %q", oldRec.Content)
	}
	if !strings.Contains(newRec.Content, "<figure>") || !strings.Contains(newRec.Content, "<mark>") {
		t.Fatalf("v2 semantics not applied: %q", newRec.Content)
	}
	// 新策略不得改变已入库文档：再次用 v2 导入其他文档后，old 内容不变
	s.Import(context.Background(), "other", in, "v2")
	again, _ := s.Get("old")
	if again.Content != oldRec.Content {
		t.Fatal("historical document changed after new policy imports")
	}
}

func TestUnknownPolicyVersion(t *testing.T) {
	s := newTestStore()
	r := s.Import(context.Background(), "x", []byte(`<p>a</p>`), "v9")
	if r.Status != StatusFailed || r.Err.Kind != ErrKindPolicy {
		t.Fatalf("got %+v", r)
	}
}

func TestBatchFailureIsolation(t *testing.T) {
	s := newTestStore()
	s.SetLimits(Limits{MaxBytes: 1 << 20})
	docs := map[string][]byte{
		"good1":      []byte(`<p>ok</p>`),
		"policy-bad": []byte(`<script>only script</script>`),
		"good2":      []byte(`<b>fine</b>`),
	}
	results := s.ImportBatch(context.Background(), docs, "v1")
	if len(results) != 3 {
		t.Fatalf("results = %d", len(results))
	}
	byID := map[string]Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	// 结果按 ID 排序
	if results[0].ID != "good1" || results[2].ID != "policy-bad" {
		t.Fatalf("results not sorted: %v", results)
	}
	if byID["good1"].Status != StatusOK || byID["good2"].Status != StatusOK {
		t.Fatal("good docs must succeed despite sibling failure")
	}
	if byID["policy-bad"].Status != StatusFailed || byID["policy-bad"].Err.Kind != ErrKindPolicy {
		t.Fatalf("policy rejection misclassified: %+v", byID["policy-bad"])
	}
	// 失败文档不得入库
	if _, ok := s.Get("policy-bad"); ok {
		t.Fatal("failed document must not be stored")
	}
	// 超限失败可区分
	big := map[string][]byte{"huge": []byte(strings.Repeat("<p>x</p>", 200000))}
	s.SetLimits(Limits{MaxBytes: 1000})
	rr := s.ImportBatch(context.Background(), big, "v1")
	if rr[0].Status != StatusFailed || rr[0].Err.Kind != ErrKindTooLarge {
		t.Fatalf("too-large misclassified: %+v", rr[0])
	}
}

func TestBatchResultsQueryable(t *testing.T) {
	s := newTestStore()
	docs := map[string][]byte{
		"a": []byte(`<p>a</p>`),
		"b": []byte(`<iframe src="https://evil"></iframe>`),
	}
	results := s.ImportBatch(context.Background(), docs, "v1")
	var okCount, failCount int
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			okCount++
		case StatusFailed:
			failCount++
			if r.Err == nil {
				t.Fatal("failed result must carry error")
			}
		}
	}
	if okCount != 1 || failCount != 1 {
		t.Fatalf("ok=%d fail=%d", okCount, failCount)
	}
}
