package sanitize

import (
	"io"
	"sort"
	"strings"
)

// Result 是一次净化的完整产物。
type Result struct {
	// HTML 是净化后的规范化输出，仅包含白名单内的安全内容。
	HTML string
	// Issues 记录解析与净化过程中发现并处理的问题。
	Issues []Issue
	// PolicyVersion 是本次净化使用的策略版本。
	PolicyVersion string
}

// dropSubtree 中的元素不在白名单时，整个子树（含文本）一并丢弃。
var dropSubtree = map[string]bool{
	"script": true, "style": true, "iframe": true, "object": true,
	"embed": true, "applet": true, "template": true, "noscript": true,
}

// Sanitize 对输入标记文本执行完整净化链路并返回规范化输出。
// 处理中断（如超限）时返回带类别的错误，不留下半写入的产物。
func Sanitize(input []byte, policyVersion string, lim Limits) (*Result, error) {
	p, ok := GetPolicy(policyVersion)
	if !ok {
		return nil, &Error{Kind: ErrKindPolicy, Message: "unknown policy version: " + policyVersion}
	}
	parsed, err := Parse(input, lim)
	if err != nil {
		return nil, err
	}
	return sanitizeParsed(parsed, p)
}

// SanitizeReader 以流式方式读取输入并净化，超限时立即失败且不产出半成品。
func SanitizeReader(r io.Reader, policyVersion string, lim Limits) (*Result, error) {
	p, ok := GetPolicy(policyVersion)
	if !ok {
		return nil, &Error{Kind: ErrKindPolicy, Message: "unknown policy version: " + policyVersion}
	}
	parsed, err := ParseReader(r, lim)
	if err != nil {
		return nil, err
	}
	return sanitizeParsed(parsed, p)
}

// sanitizeParsed 对解析结果应用策略并渲染。
func sanitizeParsed(parsed *ParseResult, p Policy) (*Result, error) {
	s := &sanitizer{policy: p, issues: parsed.Issues}
	out := s.sanitizeChildren(parsed.Doc)
	if !hasContent(out) {
		return nil, &Error{Kind: ErrKindPolicy,
			Message: "document rejected: no safe content remains after sanitizing"}
	}
	var b strings.Builder
	for _, n := range out {
		render(&b, n)
	}
	return &Result{
		HTML:          b.String(),
		Issues:        s.issues,
		PolicyVersion: p.Version,
	}, nil
}

// hasContent 判断节点列表是否含有实际内容（元素或非空白文本）。
func hasContent(nodes []*Node) bool {
	for _, n := range nodes {
		switch n.Kind {
		case KindElement:
			return true
		case KindText:
			if strings.TrimSpace(n.Data) != "" {
				return true
			}
		}
	}
	return false
}

// sanitizer 在解析树上应用白名单策略。
type sanitizer struct {
	policy Policy
	issues []Issue
}

// sanitizeChildren 净化节点的子节点列表，返回净化后的新列表。
func (s *sanitizer) sanitizeChildren(n *Node) []*Node {
	var out []*Node
	for _, c := range n.Children {
		out = append(out, s.sanitizeNode(c)...)
	}
	return out
}

// sanitizeNode 净化单个节点；被剥离的元素可能展开为多个节点或完全消失。
func (s *sanitizer) sanitizeNode(n *Node) []*Node {
	switch n.Kind {
	case KindText:
		return []*Node{{Kind: KindText, Data: n.Data, Offset: n.Offset}}
	case KindComment, KindDoctype:
		// 注释与 doctype 不出现在规范输出中。
		return nil
	case KindElement:
		rule, ok := s.policy.Elements[n.Tag]
		if !ok {
			s.issues = append(s.issues, Issue{
				Kind: IssueStrippedElement, Offset: n.Offset,
				Message: "element <" + n.Tag + "> not in whitelist, stripped",
			})
			if dropSubtree[n.Tag] {
				return nil
			}
			// 保留子内容，仅去掉外壳。
			return s.sanitizeChildren(n)
		}
		el := &Node{Kind: KindElement, Tag: n.Tag, Offset: n.Offset}
		el.Attrs = s.sanitizeAttrs(n, rule)
		el.Children = s.sanitizeChildren(n)
		for _, c := range el.Children {
			c.Parent = el
		}
		return []*Node{el}
	}
	return nil
}

// sanitizeAttrs 按元素规则过滤属性：同名属性在不同元素上的处理相互独立。
func (s *sanitizer) sanitizeAttrs(n *Node, rule ElementRule) []Attr {
	var out []Attr
	seen := map[string]bool{}
	for _, a := range n.Attrs {
		key := a.Key
		if seen[key] {
			continue // 重复属性只取第一次出现，保证确定性
		}
		seen[key] = true
		switch {
		case key == "style" && rule.AllowStyle:
			v := SanitizeStyle(a.Val, s.policy)
			if v == "" {
				s.attrIssue(n, key, "style fully stripped by policy")
				continue
			}
			if v != a.Val {
				s.attrIssue(n, key, "style declarations filtered by policy")
			}
			out = append(out, Attr{Key: "style", Val: v})
		case key == "class" && rule.AllowClass:
			v := RewriteClass(a.Val, s.policy)
			if v == "" {
				continue
			}
			out = append(out, Attr{Key: "class", Val: v})
		case key == "id" && rule.AllowID:
			v := RewriteID(a.Val, s.policy)
			if v == "" {
				continue
			}
			out = append(out, Attr{Key: "id", Val: v})
		case rule.Attrs[key]:
			v := a.Val
			if rule.URLAttrs[key] {
				checked, ok := CheckURL(v, s.policy)
				if !ok {
					s.issues = append(s.issues, Issue{
						Kind: IssueSanitizedURL, Offset: n.Offset,
						Message: "unsafe URL removed from " + n.Tag + "[" + key + "]",
					})
					continue
				}
				v = checked
			}
			out = append(out, Attr{Key: key, Val: v})
		default:
			s.attrIssue(n, key, "attribute not allowed on <"+n.Tag+">")
		}
	}
	// 属性按名排序，保证输出规范且确定。
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (s *sanitizer) attrIssue(n *Node, key, msg string) {
	s.issues = append(s.issues, Issue{
		Kind: IssueStrippedAttr, Offset: n.Offset,
		Message: n.Tag + "[" + key + "]: " + msg,
	})
}

// Render 把净化后的中间结构序列化为规范形态的标记文本。
// 输出是确定的：属性已排序、文本与属性值统一转义、空元素写法固定。
func Render(doc *Node) string {
	var b strings.Builder
	for _, c := range doc.Children {
		render(&b, c)
	}
	return b.String()
}

func render(b *strings.Builder, n *Node) {
	switch n.Kind {
	case KindText:
		b.WriteString(escapeText(n.Data))
	case KindElement:
		b.WriteByte('<')
		b.WriteString(n.Tag)
		for _, a := range n.Attrs {
			b.WriteByte(' ')
			b.WriteString(a.Key)
			b.WriteString(`="`)
			b.WriteString(escapeAttr(a.Val))
			b.WriteByte('"')
		}
		b.WriteByte('>')
		if voidElements[n.Tag] {
			return
		}
		for _, c := range n.Children {
			render(b, c)
		}
		b.WriteString("</")
		b.WriteString(n.Tag)
		b.WriteByte('>')
	}
}

// escapeText 转义文本节点内容。
func escapeText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// escapeAttr 转义属性值。
func escapeAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
