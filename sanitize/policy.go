package sanitize

// Policy 是按版本管理的白名单净化策略。
// 只有明确允许的元素、属性与取值能出现在输出里。
type Policy struct {
	Version string
	// Elements 是允许保留的元素名集合。
	Elements map[string]bool
	// Attributes 按元素给出允许的属性名；"*" 键对所有元素生效。
	// 同名属性落在不同元素上的处理可以不同。
	Attributes map[string]map[string]bool
	// URLAttrs 按元素给出需要按 URL 规则校验的属性。
	URLAttrs map[string]map[string]bool
	// AllowRelativeURLs 控制相对地址是否放行。
	AllowRelativeURLs bool
	// AllowedStyles 是内联样式中允许保留的 CSS 属性。
	AllowedStyles map[string]bool
	// DropElements 的元素连同整个子树一起剥离（如 script/style）。
	DropElements map[string]bool
	// RewriteIdents 为真时对 class 与 id 做稳定重写。
	RewriteIdents bool
	// IdentScope 是标识重写的作用域，默认取 Version。
	IdentScope string
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// DefaultPolicy 返回当前默认策略（v1）。
func DefaultPolicy() *Policy {
	return &Policy{
		Version: "v1",
		Elements: set(
			"p", "br", "hr", "div", "span",
			"h1", "h2", "h3", "h4", "h5", "h6",
			"strong", "em", "b", "i", "u", "s", "code", "pre", "blockquote",
			"ul", "ol", "li",
			"a", "img",
			"table", "thead", "tbody", "tr", "th", "td",
		),
		Attributes: map[string]map[string]bool{
			"*":   set("class", "id", "style", "title", "dir", "lang"),
			"a":   set("href", "name"),
			"img": set("src", "alt", "width", "height"),
			"td":  set("colspan", "rowspan"),
			"th":  set("colspan", "rowspan"),
		},
		URLAttrs: map[string]map[string]bool{
			"a":   set("href"),
			"img": set("src"),
		},
		AllowRelativeURLs: true,
		AllowedStyles: set(
			"color", "background-color", "font-size", "font-weight", "font-style",
			"text-align", "text-decoration", "margin", "margin-left", "margin-right",
			"padding", "padding-left", "padding-right", "width", "height",
		),
		DropElements:  set("script", "style", "iframe", "object", "embed", "form", "textarea", "button", "select", "noscript", "template"),
		RewriteIdents: true,
	}
}

// PolicyV2 返回 v2 策略：在 v1 基础上扩展少量元素与属性，
// 用于验证策略版本共存；历史文档仍按 v1 语义读取。
func PolicyV2() *Policy {
	p := DefaultPolicy()
	p.Version = "v2"
	p.Elements["figure"] = true
	p.Elements["figcaption"] = true
	p.Elements["mark"] = true
	p.Attributes["img"]["loading"] = true
	p.AllowedStyles["border"] = true
	return p
}

// Sanitize 按策略过滤中间结构，返回净化后的根节点（新树，不改输入）。
func (p *Policy) Sanitize(doc *Node) *Node {
	out := &Node{Type: DocumentNode, Pos: doc.Pos}
	for _, c := range doc.Children {
		p.sanitizeNode(c, out)
	}
	return out
}

func (p *Policy) sanitizeNode(n *Node, parent *Node) {
	switch n.Type {
	case TextNode:
		parent.AppendChild(&Node{Type: TextNode, Data: n.Data, Pos: n.Pos})
	case CommentNode:
		// 注释一律剥离
	case ElementNode:
		if p.DropElements[n.Data] {
			return // 连同子树剥离
		}
		if !p.Elements[n.Data] {
			// 未知元素：剥离标签但保留子内容（unwrap）
			for _, c := range n.Children {
				p.sanitizeNode(c, parent)
			}
			return
		}
		el := &Node{Type: ElementNode, Data: n.Data, Pos: n.Pos}
		el.Attr = p.sanitizeAttrs(n)
		parent.AppendChild(el)
		for _, c := range n.Children {
			p.sanitizeNode(c, el)
		}
	}
}

func (p *Policy) sanitizeAttrs(n *Node) []Attribute {
	var out []Attribute
	scope := p.IdentScope
	if scope == "" {
		scope = p.Version
	}
	for _, a := range n.Attr {
		if !p.attrAllowed(n.Data, a.Key) {
			continue
		}
		val := a.Val
		// URL 属性按协议规则校验，不安全则剥离该属性
		if p.URLAttrs[n.Data][a.Key] {
			cleaned, ok := CheckURL(val, p.AllowRelativeURLs)
			if !ok {
				continue
			}
			val = cleaned
		}
		switch a.Key {
		case "style":
			val = SanitizeStyle(val, p.AllowedStyles)
			if val == "" {
				continue
			}
		case "class":
			if p.RewriteIdents {
				val = RewriteClassList(scope, val)
				if val == "" {
					continue
				}
			}
		case "id":
			if p.RewriteIdents {
				val = RewriteIdent(scope, val)
			}
		}
		out = append(out, Attribute{Key: a.Key, Val: val})
	}
	return out
}

// attrAllowed 结合元素与属性名判断是否放行："*" 全局规则与元素规则取并集。
func (p *Policy) attrAllowed(elem, attr string) bool {
	if g, ok := p.Attributes["*"]; ok && g[attr] {
		return true
	}
	if per, ok := p.Attributes[elem]; ok && per[attr] {
		return true
	}
	return false
}
