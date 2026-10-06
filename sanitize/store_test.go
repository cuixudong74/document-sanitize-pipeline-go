package sanitize

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestStoreImportIdempotent(t *testing.T) {
	s := NewStore()
	input := []byte(`<p>hello</p>`)
	d1, err := s.Import(input, PolicyV1, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s.Import(input, PolicyV1, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if d1.ID != d2.ID {
		t.Fatalf("re-import produced different ID: %s vs %s", d1.ID, d2.ID)
	}
	if d1 != d2 {
		t.Fatal("re-import should return the same record")
	}
	if s.Len() != 1 {
		t.Fatalf("want 1 doc, got %d", s.Len())
	}
}

func TestStoreImportDifferentPolicyDifferentDoc(t *testing.T) {
	s := NewStore()
	input := []byte(`<p class="x">hello</p>`)
	d1, err := s.Import(input, PolicyV1, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s.Import(input, PolicyV2, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if d1.ID == d2.ID {
		t.Fatal("different policy versions must produce different docs")
	}
	// v1 不含 class，v2 重写保留——历史文档内容不受新策略影响。
	if strings.Contains(d1.HTML, "class") {
		t.Fatalf("v1 doc should not contain class: %q", d1.HTML)
	}
	if !strings.Contains(d2.HTML, `class="doc-x"`) {
		t.Fatalf("v2 doc should contain rewritten class: %q", d2.HTML)
	}
	if s.Len() != 2 {
		t.Fatalf("want 2 docs, got %d", s.Len())
	}
}

// 并发导入同一内容：结果确定且无重复副作用。
func TestStoreConcurrentImport(t *testing.T) {
	s := NewStore()
	input := []byte(`<p>concurrent <b>test</b></p>`)
	const n = 32
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, err := s.Import(input, PolicyV1, Limits{})
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = d.ID
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("concurrent imports diverged: %s vs %s", ids[i], ids[0])
		}
	}
	if s.Len() != 1 {
		t.Fatalf("want 1 doc after concurrent import, got %d", s.Len())
	}
}

// 并发导入不同内容：全部成功且互不干扰。
func TestStoreConcurrentDistinct(t *testing.T) {
	s := NewStore()
	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Import([]byte(fmt.Sprintf("<p>doc %d</p>", i)), PolicyV1, Limits{})
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if s.Len() != n {
		t.Fatalf("want %d docs, got %d", n, s.Len())
	}
}

func TestStoreGet(t *testing.T) {
	s := NewStore()
	d, err := s.Import([]byte(`<p>x</p>`), PolicyV1, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(d.ID)
	if !ok || got != d {
		t.Fatal("Get should return imported doc")
	}
	if _, ok := s.Get("nonexistent"); ok {
		t.Fatal("Get should miss for unknown ID")
	}
}
