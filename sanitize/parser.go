package sanitize

import (
	"bytes"
	"io"
	"strings"
)

// ParseIssue 记录解析恢复过程中发现的问题及其位置。
type ParseIssue struct {
	Message string
	Pos     Position
}

// ParseResult 包含恢复后的文档结构与解析问题列表。
type ParseResult struct {
	Doc    *Node
	Issues []ParseIssue
}

// voidElements 是没有闭合标签的元素。
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

// closesP 列出的块级元素出现时会隐式闭合未闭合的 <p>。
var closesP = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true,
	"div": true, "dl": true, "fieldset": true, "figure": true, "footer": true,
	"form": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true,
	"h6": true, "header": true, "hr": true, "main": true, "nav": true,
	"ol": true, "p": true, "pre": true, "section": true, "table": true,
	"ul": true,
}

// Parse 从 reader 容错解析标记文本。单处畸形不会导致整篇失败，
// 恢复动作会记录到 Issues 中并带原始字节偏移。
func Parse(r io.Reader, maxBytes int64) (*ParseResult, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 30
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, &Error{Kind: ErrKindTooLarge, Message: "input exceeds size limit"}
	}
	p := &parser{data: data, res: &ParseResult{Doc: &Node{Type: DocumentNode}}}
	p.res.Doc.Pos = Position{0, len(data)}
	p.run()
	return p.res, nil
}

type parser struct {
	data []byte
	pos  int
	res  *ParseResult
}

func (p *parser) issue(msg string, start, end int) {
	p.res.Issues = append(p.res.Issues, ParseIssue{Message: msg, Pos: Position{start, end}})
}

func (p *parser) run() {
	stack := []*Node{p.res.Doc}
	top := func() *Node { return stack[len(stack)-1] }

	for p.pos < len(p.data) {
		start := p.pos
		if p.data[p.pos] != '<' {
			// 文本直到下一个 '<'
			next := bytes.IndexByte(p.data[p.pos:], '<')
			end := len(p.data)
			if next >= 0 {
				end = p.pos + next
			}
			top().AppendChild(&Node{Type: TextNode, Data: DecodeEntities(string(p.data[p.pos:end])), Pos: Position{p.pos, end}})
			p.pos = end
			continue
		}
		// 处理 '<' 开头
		if p.pos+1 >= len(p.data) {
			// 末尾孤立 '<'，按文本处理
			p.issue("stray '<' at end of input", start, len(p.data))
			top().AppendChild(&Node{Type: TextNode, Data: "<", Pos: Position{start, len(p.data)}})
			p.pos = len(p.data)
			break
		}
		c := p.data[p.pos+1]
		switch {
		case c == '!':
			p.parseMarkupDeclaration(top())
		case c == '/':
			p.parseEndTag(&stack)
		case isTagNameStart(c):
			p.parseStartTag(&stack)
		default:
			// '<' 后面不是合法标签开头，按文本恢复
			p.issue("'<' not followed by tag, treated as text", start, start+1)
			top().AppendChild(&Node{Type: TextNode, Data: "<", Pos: Position{start, start + 1}})
			p.pos = start + 1
		}
	}
	// EOF 时仍未闭合的元素：记录问题并隐式闭合
	for _, n := range stack[1:] {
		p.issue("unclosed element <"+n.Data+"> implicitly closed at EOF", n.Pos.Start, n.Pos.End)
	}
}

func (p *parser) parseMarkupDeclaration(parent *Node) {
	start := p.pos
	rest := p.data[p.pos:]
	if bytes.HasPrefix(rest, []byte("<!--")) {
		end := bytes.Index(rest[4:], []byte("-->"))
		if end < 0 {
			p.issue("unterminated comment", start, len(p.data))
			parent.AppendChild(&Node{Type: CommentNode, Data: string(rest[4:]), Pos: Position{start, len(p.data)}})
			p.pos = len(p.data)
			return
		}
		parent.AppendChild(&Node{Type: CommentNode, Data: string(rest[4 : 4+end]), Pos: Position{start, start + 4 + end + 3}})
		p.pos = start + 4 + end + 3
		return
	}
	// doctype 或其他声明：跳过到 '>'
	gt := bytes.IndexByte(rest, '>')
	if gt < 0 {
		p.issue("unterminated markup declaration", start, len(p.data))
		p.pos = len(p.data)
		return
	}
	p.pos = start + gt + 1
}

func (p *parser) parseEndTag(stack *[]*Node) {
	start := p.pos
	p.pos += 2 // 跳过 "</"
	nameStart := p.pos
	for p.pos < len(p.data) && isTagNameChar(p.data[p.pos]) {
		p.pos++
	}
	name := strings.ToLower(string(p.data[nameStart:p.pos]))
	// 跳过标签内剩余内容直到 '>'
	gt := bytes.IndexByte(p.data[p.pos:], '>')
	if gt < 0 {
		p.issue("unterminated end tag </"+name+">", start, len(p.data))
		p.pos = len(p.data)
		return
	}
	p.pos += gt + 1
	if name == "" {
		p.issue("empty end tag ignored", start, p.pos)
		return
	}
	// 在栈中寻找匹配元素
	s := *stack
	idx := -1
	for i := len(s) - 1; i >= 1; i-- {
		if s[i].Data == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		p.issue("unmatched end tag </"+name+"> ignored", start, p.pos)
		return
	}
	// 隐式闭合其上的所有元素
	for i := len(s) - 1; i > idx; i-- {
		p.issue("element <"+s[i].Data+"> implicitly closed by </"+name+">", s[i].Pos.Start, s[i].Pos.End)
	}
	s[idx].Pos.End = p.pos
	*stack = s[:idx]
}

func (p *parser) parseStartTag(stack *[]*Node) {
	start := p.pos
	p.pos++ // 跳过 '<'
	nameStart := p.pos
	for p.pos < len(p.data) && isTagNameChar(p.data[p.pos]) {
		p.pos++
	}
	name := strings.ToLower(string(p.data[nameStart:p.pos]))
	el := &Node{Type: ElementNode, Data: name, Pos: Position{Start: start}}

	// 解析属性
	for {
		p.skipSpace()
		if p.pos >= len(p.data) {
			p.issue("unterminated start tag <"+name+">", start, len(p.data))
			break
		}
		if p.data[p.pos] == '>' {
			p.pos++
			break
		}
		if p.data[p.pos] == '/' && p.pos+1 < len(p.data) && p.data[p.pos+1] == '>' {
			el.Pos.End = p.pos + 2
			p.pos += 2
			p.finishElement(stack, el, true)
			return
		}
		attr := p.parseAttr()
		if attr.Key != "" {
			el.Attr = append(el.Attr, attr)
		}
	}
	el.Pos.End = p.pos
	p.finishElement(stack, el, false)
}

// finishElement 处理隐式闭合规则并把元素挂到树上。
func (p *parser) finishElement(stack *[]*Node, el *Node, selfClosing bool) {
	s := *stack
	// <li> 遇到同级 <li> 时隐式闭合
	if el.Data == "li" {
		for i := len(s) - 1; i >= 1; i-- {
			if s[i].Data == "li" {
				p.issue("element <li> implicitly closed by new <li>", s[i].Pos.Start, s[i].Pos.End)
				s = s[:i]
			}
			if s[len(s)-1].Data != "li" {
				break
			}
		}
	}
	// 块级元素隐式闭合未闭合的 <p>
	if closesP[el.Data] && len(s) >= 2 && s[len(s)-1].Data == "p" {
		p.issue("element <p> implicitly closed by <"+el.Data+">", s[len(s)-1].Pos.Start, s[len(s)-1].Pos.End)
		s = s[:len(s)-1]
	}
	top := s[len(s)-1]
	top.AppendChild(el)
	*stack = s
	if !selfClosing && !voidElements[el.Data] {
		*stack = append(*stack, el)
	}
}

func (p *parser) parseAttr() Attribute {
	start := p.pos
	for p.pos < len(p.data) && !isSpace(p.data[p.pos]) && p.data[p.pos] != '=' && p.data[p.pos] != '>' && p.data[p.pos] != '/' {
		p.pos++
	}
	key := strings.ToLower(string(p.data[start:p.pos]))
	p.skipSpace()
	if p.pos >= len(p.data) || p.data[p.pos] != '=' {
		return Attribute{Key: key}
	}
	p.pos++
	p.skipSpace()
	if p.pos >= len(p.data) {
		return Attribute{Key: key}
	}
	var val string
	if q := p.data[p.pos]; q == '"' || q == '\'' {
		p.pos++
		vstart := p.pos
		for p.pos < len(p.data) && p.data[p.pos] != q {
			p.pos++
		}
		val = string(p.data[vstart:p.pos])
		if p.pos < len(p.data) {
			p.pos++ // 跳过引号
		} else {
			p.issue("unterminated attribute value", vstart, len(p.data))
		}
	} else {
		vstart := p.pos
		for p.pos < len(p.data) && !isSpace(p.data[p.pos]) && p.data[p.pos] != '>' {
			p.pos++
		}
		val = string(p.data[vstart:p.pos])
	}
	return Attribute{Key: key, Val: DecodeEntities(val)}
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) && isSpace(p.data[p.pos]) {
		p.pos++
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

func isTagNameStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isTagNameChar(c byte) bool {
	return isTagNameStart(c) || (c >= '0' && c <= '9') || c == '-' || c == ':'
}
