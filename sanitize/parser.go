package sanitize

import (
	"fmt"
	"io"
)

// ParseResult 是容错解析的产物：恢复后的文档树 + 问题列表。
type ParseResult struct {
	Doc    *Node
	Issues []Issue
}

// Parse 把输入的标记文本解析为统一中间结构。
// 解析容忍畸形标签、未闭合标签与非法嵌套，不因单处畸形整篇失败；
// 恢复过程中发现的问题以 Issue 形式记录，可定位到原始输入位置。
func Parse(input []byte, lim Limits) (*ParseResult, error) {
	lim = lim.withDefaults()
	if len(input) > lim.MaxBytes {
		return nil, &Error{Kind: ErrKindTooLarge,
			Message: fmt.Sprintf("input size %d exceeds limit %d", len(input), lim.MaxBytes)}
	}
	return parse(newTokenizer(input), lim)
}

// ParseReader 以流式方式解析：输入通过有界 reader 读入，
// 超过 Limits.MaxBytes 立即返回 *Error（ErrKindTooLarge），不产出半成品。
func ParseReader(r io.Reader, lim Limits) (*ParseResult, error) {
	lim = lim.withDefaults()
	t, err := newStreamTokenizer(r, lim)
	if err != nil {
		if e, ok := err.(*Error); ok {
			return nil, e
		}
		return nil, &Error{Kind: ErrKindParse, Message: err.Error()}
	}
	return parse(t, lim)
}

// voidElements 是没有内容、不需要结束标签的元素。
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"source": true, "track": true, "wbr": true,
}

// closesP 是出现时会隐式关闭未闭合 <p> 的块级元素。
var closesP = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true,
	"div": true, "dl": true, "fieldset": true, "figure": true, "footer": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"header": true, "hr": true, "ol": true, "p": true, "pre": true,
	"section": true, "table": true, "ul": true,
}

// parser 是容错树构建器。
type parser struct {
	t      *tokenizer
	lim    Limits
	issues []Issue
	nodes  int
	stack  []*Node // 打开元素栈，栈底是文档根
}

func parse(t *tokenizer, lim Limits) (*ParseResult, error) {
	root := &Node{Kind: KindDocument}
	p := &parser{t: t, lim: lim, stack: []*Node{root}}
	if err := p.run(); err != nil {
		return nil, err
	}
	return &ParseResult{Doc: root, Issues: p.issues}, nil
}

func (p *parser) run() error {
	for {
		tok := p.t.next()
		if tok.issue != nil {
			p.issues = append(p.issues, *tok.issue)
		}
		switch tok.kind {
		case tokEOF:
			p.closeAll()
			return nil
		case tokText:
			if tok.data == "" {
				continue
			}
			if err := p.append(&Node{Kind: KindText, Data: tok.data, Offset: tok.offset}); err != nil {
				return err
			}
		case tokComment:
			if err := p.append(&Node{Kind: KindComment, Data: tok.data, Offset: tok.offset}); err != nil {
				return err
			}
		case tokDoctype:
			if err := p.append(&Node{Kind: KindDoctype, Data: tok.data, Offset: tok.offset}); err != nil {
				return err
			}
		case tokStartTag:
			if err := p.startTag(tok); err != nil {
				return err
			}
		case tokEndTag:
			p.endTag(tok)
		}
	}
}

// append 把节点挂到当前打开元素下，并检查节点数上限。
func (p *parser) append(n *Node) error {
	p.nodes++
	if p.nodes > p.lim.MaxNodes {
		return &Error{Kind: ErrKindTooLarge,
			Message: fmt.Sprintf("node count exceeds limit %d", p.lim.MaxNodes)}
	}
	parent := p.stack[len(p.stack)-1]
	n.Parent = parent
	parent.Children = append(parent.Children, n)
	return nil
}

// startTag 处理开始标签，含非法嵌套恢复。
func (p *parser) startTag(tok token) error {
	tag := tok.data
	// 恢复规则 1：块级元素隐式关闭未闭合的 <p>。
	if closesP[tag] {
		if idx := p.findOpen("p"); idx >= 0 {
			p.issues = append(p.issues, Issue{
				Kind: IssueIllegalNesting, Offset: tok.offset, Line: tok.line, Column: tok.col,
				Message: fmt.Sprintf("<%s> implicitly closes unclosed <p>", tag),
			})
			p.popTo(idx)
		}
	}
	// 恢复规则 2：<li> 隐式关闭未闭合的 <li>。
	if tag == "li" {
		if idx := p.findOpenWithin("li", "ul", "ol"); idx >= 0 {
			p.issues = append(p.issues, Issue{
				Kind: IssueIllegalNesting, Offset: tok.offset, Line: tok.line, Column: tok.col,
				Message: "<li> implicitly closes unclosed <li>",
			})
			p.popTo(idx)
		}
	}
	// 恢复规则 3：表格单元格/行的相互隐式关闭。
	if tag == "td" || tag == "th" {
		if idx := p.findOpenWithin("td", "tr"); idx >= 0 {
			p.issues = append(p.issues, Issue{
				Kind: IssueIllegalNesting, Offset: tok.offset, Line: tok.line, Column: tok.col,
				Message: fmt.Sprintf("<%s> implicitly closes unclosed <td/th>", tag),
			})
			p.popTo(idx)
		}
		if idx := p.findOpenWithin("th", "tr"); idx >= 0 {
			p.issues = append(p.issues, Issue{
				Kind: IssueIllegalNesting, Offset: tok.offset, Line: tok.line, Column: tok.col,
				Message: fmt.Sprintf("<%s> implicitly closes unclosed <td/th>", tag),
			})
			p.popTo(idx)
		}
	}
	if tag == "tr" {
		for _, cell := range []string{"td", "th"} {
			if idx := p.findOpenWithin(cell, "table", "tbody", "thead", "tfoot"); idx >= 0 {
				p.issues = append(p.issues, Issue{
					Kind: IssueIllegalNesting, Offset: tok.offset, Line: tok.line, Column: tok.col,
					Message: "<tr> implicitly closes unclosed table cell",
				})
				p.popTo(idx)
			}
		}
		if idx := p.findOpenWithin("tr", "table", "tbody", "thead", "tfoot"); idx >= 0 {
			p.issues = append(p.issues, Issue{
				Kind: IssueIllegalNesting, Offset: tok.offset, Line: tok.line, Column: tok.col,
				Message: "<tr> implicitly closes unclosed <tr>",
			})
			p.popTo(idx)
		}
	}

	el := &Node{Kind: KindElement, Tag: tag, Attrs: tok.attrs, Offset: tok.offset}
	if err := p.append(el); err != nil {
		return err
	}
	if voidElements[tag] || tok.selfClose {
		return nil
	}
	if len(p.stack) >= p.lim.MaxDepth {
		return &Error{Kind: ErrKindTooLarge,
			Message: fmt.Sprintf("nesting depth exceeds limit %d", p.lim.MaxDepth)}
	}
	p.stack = append(p.stack, el)
	return nil
}

// endTag 处理结束标签：找到匹配的打开元素并隐式关闭其上的所有元素；
// 找不到则作为多余结束标签忽略。
func (p *parser) endTag(tok token) {
	idx := p.findOpen(tok.data)
	if idx < 0 {
		p.issues = append(p.issues, Issue{
			Kind: IssueStrayEndTag, Offset: tok.offset, Line: tok.line, Column: tok.col,
			Message: fmt.Sprintf("stray end tag </%s> ignored", tok.data),
		})
		return
	}
	// 栈中位于匹配元素之上的元素都是未闭合的。
	for i := len(p.stack) - 1; i > idx; i-- {
		el := p.stack[i]
		p.issues = append(p.issues, Issue{
			Kind: IssueUnclosedTag, Offset: tok.offset, Line: tok.line, Column: tok.col,
			Message: fmt.Sprintf("<%s> implicitly closed by </%s>", el.Tag, tok.data),
		})
	}
	p.popTo(idx)
}

// closeAll 在输入结束时关闭所有未闭合元素。
func (p *parser) closeAll() {
	for len(p.stack) > 1 {
		el := p.stack[len(p.stack)-1]
		p.issues = append(p.issues, Issue{
			Kind: IssueUnclosedTag, Offset: el.Offset,
			Message: fmt.Sprintf("<%s> implicitly closed at end of input", el.Tag),
		})
		p.stack = p.stack[:len(p.stack)-1]
	}
}

// findOpen 在打开元素栈中查找标签（不含文档根），返回栈下标或 -1。
func (p *parser) findOpen(tag string) int {
	for i := len(p.stack) - 1; i >= 1; i-- {
		if p.stack[i].Tag == tag {
			return i
		}
	}
	return -1
}

// findOpenWithin 在栈中查找 tag，但查找范围不超过最近的 scope 边界元素。
func (p *parser) findOpenWithin(tag string, scopes ...string) int {
	for i := len(p.stack) - 1; i >= 1; i-- {
		t := p.stack[i].Tag
		if t == tag {
			return i
		}
		for _, s := range scopes {
			if t == s {
				return -1
			}
		}
	}
	return -1
}

// popTo 弹出栈顶直到并包含下标 idx 的元素。
func (p *parser) popTo(idx int) {
	p.stack = p.stack[:idx]
}
