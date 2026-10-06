package sanitize

import (
	"strings"
	"testing"
)

// 策略版本兼容：同一输入在不同版本下产出不同但各自稳定的结果；
// 已入库的 v1 文档在 v2 注册后内容不变。
func TestPolicyVersionCompat(t *testing.T) {
	s := NewStore()
	input := []byte(`<p class="keep" style="color:red">v</p>`)

	d1, err := s.Import(input, PolicyV1, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	v1HTML := d1.HTML

	d2, err := s.Import(input, PolicyV2, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d2.HTML, `class="doc-keep"`) || !strings.Contains(d2.HTML, "color: red") {
		t.Fatalf("v2 output unexpected: %q", d2.HTML)
	}

	// 重新读取 v1 文档：内容保持导入时的策略语义。
	again, ok := s.Get(d1.ID)
	if !ok || again.HTML != v1HTML {
		t.Fatal("v1 doc content changed after v2 import")
	}
}

// 同版本策略重复注册语义不同必须 panic（语义不可变）。
func TestPolicyReregisterConflictPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic on conflicting re-registration")
		}
	}()
	p := builtinV1()
	p.AllowRelativeURL = false // 改变语义
	RegisterPolicy(p)
}

// 同版本同内容重复注册是安全的（幂等注册）。
func TestPolicyReregisterIdenticalOK(t *testing.T) {
	RegisterPolicy(builtinV1())
	if _, ok := GetPolicy(PolicyV1); !ok {
		t.Fatal("v1 policy missing")
	}
}
