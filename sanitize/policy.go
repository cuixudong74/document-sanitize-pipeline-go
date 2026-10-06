package sanitize

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Policy 是一份按版本管理的净化策略。
// 同一版本的策略语义不可变；新需求通过注册新版本承载，
// 历史文档按其导入时的版本语义保持可读。
type Policy struct {
	Version string

	// Elements 是允许出现的元素白名单（小写标签名）。
	Elements map[string]ElementRule

	// URLSchemes 是链接/资源地址允许的协议（小写，不含冒号）。
	// 相对地址是否放行由 AllowRelativeURL 控制。
	URLSchemes       map[string]bool
	AllowRelativeURL bool

	// CSSProperties 是内联样式允许保留的属性（小写）。
	CSSProperties map[string]bool

	// ClassPrefix 是类名与 id 重写时添加的稳定前缀，
	// 避免与宿主页面其余部分冲突。
	ClassPrefix string

	// DropComments 为 true 时剥离注释节点。
	DropComments bool
}

// ElementRule 描述单个元素上的属性白名单。
// 属性是否放行结合所在元素判断，同名属性在不同元素上可区别对待。
type ElementRule struct {
	// Attrs 是该元素允许的属性名（小写）。
	Attrs map[string]bool
	// URLAttrs 是需要做 URL 校验的属性名（Attrs 的子集）。
	URLAttrs map[string]bool
	// AllowStyle 为 true 时允许 style 属性（内容仍按 CSSProperties 过滤）。
	AllowStyle bool
	// AllowClass 为 true 时允许 class 属性（值会被稳定重写）。
	AllowClass bool
	// AllowID 为 true 时允许 id 属性（值会被稳定重写）。
	AllowID bool
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Policy{}
)

// RegisterPolicy 注册一个策略版本。重复注册相同版本但内容不同会 panic，
// 保证“策略语义按版本不可变”这一约束在进程内被强制执行。
func RegisterPolicy(p Policy) {
	if p.Version == "" {
		panic("sanitize: policy version must not be empty")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if existing, ok := registry[p.Version]; ok {
		if existing.fingerprint() != p.fingerprint() {
			panic(fmt.Sprintf("sanitize: policy version %q re-registered with different semantics", p.Version))
		}
		return
	}
	registry[p.Version] = p
}

// GetPolicy 按版本号获取策略，未注册时返回 false。
func GetPolicy(version string) (Policy, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := registry[version]
	return p, ok
}

// fingerprint 生成策略内容的稳定指纹，用于检测同版本语义漂移。
func (p Policy) fingerprint() string {
	var b strings.Builder
	b.WriteString(p.Version)
	b.WriteByte('|')
	for _, name := range sortedKeys(p.Elements) {
		r := p.Elements[name]
		b.WriteString(name)
		b.WriteString("{a:")
		b.WriteString(strings.Join(sortedKeys(r.Attrs), ","))
		b.WriteString(";u:")
		b.WriteString(strings.Join(sortedKeys(r.URLAttrs), ","))
		fmt.Fprintf(&b, ";s:%v;c:%v;i:%v}", r.AllowStyle, r.AllowClass, r.AllowID)
	}
	b.WriteString("|schemes:")
	b.WriteString(strings.Join(sortedKeys(p.URLSchemes), ","))
	fmt.Fprintf(&b, ";rel:%v", p.AllowRelativeURL)
	b.WriteString("|css:")
	b.WriteString(strings.Join(sortedKeys(p.CSSProperties), ","))
	fmt.Fprintf(&b, "|prefix:%q|dropComments:%v", p.ClassPrefix, p.DropComments)
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// 内置策略版本号。
const (
	// PolicyV1 是基础策略：严格的结构元素与最小属性集。
	PolicyV1 = "v1"
	// PolicyV2 在 v1 基础上扩展：更多元素、内联样式与类名（重写后保留）。
	PolicyV2 = "v2"
)

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// builtinV1 返回内置 v1 策略。
func builtinV1() Policy {
	textRule := ElementRule{}
	return Policy{
		Version: PolicyV1,
		Elements: map[string]ElementRule{
			"p":          textRule,
			"br":         textRule,
			"hr":         textRule,
			"div":        textRule,
			"span":       textRule,
			"blockquote": textRule,
			"pre":        textRule,
			"b":          textRule,
			"strong":     textRule,
			"i":          textRule,
			"em":         textRule,
			"u":          textRule,
			"s":          textRule,
			"code":       textRule,
			"h1":         textRule,
			"h2":         textRule,
			"h3":         textRule,
			"h4":         textRule,
			"h5":         textRule,
			"h6":         textRule,
			"ul":         textRule,
			"ol":         textRule,
			"li":         textRule,
			"table":      textRule,
			"thead":      textRule,
			"tbody":      textRule,
			"tr":         textRule,
			"td":         {Attrs: set("colspan", "rowspan")},
			"th":         {Attrs: set("colspan", "rowspan")},
			"a":          {Attrs: set("href", "title"), URLAttrs: set("href")},
			"img":        {Attrs: set("src", "alt", "title", "width", "height"), URLAttrs: set("src")},
		},
		URLSchemes:       set("http", "https", "mailto"),
		AllowRelativeURL: true,
		CSSProperties:    set(),
		ClassPrefix:      "doc-",
		DropComments:     true,
	}
}

// builtinV2 返回内置 v2 策略：在 v1 之上放开样式与类名（重写后保留）。
func builtinV2() Policy {
	p := builtinV1()
	p.Version = PolicyV2
	// 深拷贝元素表，避免与 v1 共享底层 map。
	elems := make(map[string]ElementRule, len(p.Elements)+4)
	for k, v := range p.Elements {
		elems[k] = v
	}
	// 全局放行 class/id（重写后保留）与受控 style。
	for name, rule := range elems {
		rule.AllowClass = true
		rule.AllowID = true
		rule.AllowStyle = true
		elems[name] = rule
	}
	// v2 新增元素。
	elems["figure"] = ElementRule{AllowClass: true, AllowID: true, AllowStyle: true}
	elems["figcaption"] = ElementRule{AllowClass: true, AllowID: true, AllowStyle: true}
	elems["section"] = ElementRule{AllowClass: true, AllowID: true, AllowStyle: true}
	elems["article"] = ElementRule{AllowClass: true, AllowID: true, AllowStyle: true}
	p.Elements = elems
	p.CSSProperties = set(
		"color", "background-color", "font-size", "font-weight", "font-style",
		"text-align", "text-decoration", "margin", "margin-left", "margin-right",
		"margin-top", "margin-bottom", "padding", "padding-left", "padding-right",
		"padding-top", "padding-bottom", "border", "border-color", "border-width",
		"border-style", "width", "height", "line-height", "vertical-align",
	)
	return p
}

func init() {
	RegisterPolicy(builtinV1())
	RegisterPolicy(builtinV2())
}
