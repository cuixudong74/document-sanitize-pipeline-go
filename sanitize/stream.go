package sanitize

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Limits 控制流式处理的资源上限。
type Limits struct {
	// MaxBytes 是单篇文档允许的最大输入字节数，<=0 时使用默认值。
	MaxBytes int64
}

// DefaultMaxBytes 是默认的单篇文档大小上限。
const DefaultMaxBytes = 16 << 20 // 16 MiB

// maxTagSize 是单个标签允许的最大字节数，超过按文本恢复，保证内存有界。
const maxTagSize = 64 << 10

// StreamResult 描述一次流式净化的结果。
type StreamResult struct {
	Issues   []ParseIssue
	BytesIn  int64
	BytesOut int64
}

// SanitizeStream 流式读取 src，净化后写入 dst。
//
// 内存占用只与标签嵌套深度成正比，不随输入长度线性增长。
// 输出先写入临时文件，全部成功后才提交到 dst；处理中断或失败时
// dst 不会留下半写入的产物。超过上限返回 Kind 为 ErrKindTooLarge 的错误。
func SanitizeStream(src io.Reader, dst io.Writer, p *Policy, lim Limits) (*StreamResult, error) {
	max := lim.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	cr := &countingReader{r: src, max: max}
	tz := newStreamTokenizer(cr)

	// 输出暂存到临时文件，成功后一次性提交
	var tmp *os.File
	var err error
	if f, ok := dst.(*os.File); ok {
		// 与目标同目录，成功后 rename 实现原子替换
		tmp, err = os.CreateTemp(filepath.Dir(f.Name()), ".sanitize-*")
	} else {
		tmp, err = os.CreateTemp("", "sanitize-*")
	}
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			os.Remove(tmpName)
		}
	}()

	w := bufio.NewWriter(tmp)
	res := &StreamResult{}
	err = streamSanitize(tz, w, p, res)
	if err == nil {
		err = w.Flush()
	}
	if err != nil {
		return nil, err
	}
	res.BytesIn = cr.n
	res.BytesOut, _ = tmp.Seek(0, io.SeekCurrent)
	res.Issues = tz.issues

	if f, ok := dst.(*os.File); ok {
		if err := tmp.Close(); err != nil {
			return nil, err
		}
		if err := os.Rename(tmpName, f.Name()); err != nil {
			return nil, err
		}
		committed = true
		return res, nil
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.Copy(dst, tmp); err != nil {
		return nil, err
	}
	committed = true
	return res, nil
}

// countingReader 统计读取字节并在超过上限时返回可分类错误。
type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, &Error{Kind: ErrKindTooLarge, Message: "input exceeds size limit"}
	}
	return n, err
}

// ---- 流式分词 ----

type tokKind int

const (
	tokEOF tokKind = iota
	tokText
	tokStart
	tokEnd
)

type token struct {
	kind        tokKind
	data        string // 文本内容或元素名
	attr        []Attribute
	selfClosing bool
	pos         Position
}

type streamTokenizer struct {
	br     *bufio.Reader
	pos    int
	issues []ParseIssue
}

func newStreamTokenizer(r io.Reader) *streamTokenizer {
	return &streamTokenizer{br: bufio.NewReaderSize(r, 32<<10)}
}

func (t *streamTokenizer) issue(msg string, start, end int) {
	t.issues = append(t.issues, ParseIssue{Message: msg, Pos: Position{start, end}})
}

func (t *streamTokenizer) readByte() (byte, error) {
	b, err := t.br.ReadByte()
	if err == nil {
		t.pos++
	}
	return b, err
}

func (t *streamTokenizer) unreadByte() {
	t.br.UnreadByte()
	t.pos--
}

// next 读取下一个 token；输入畸形时尽量恢复为文本。
func (t *streamTokenizer) next() (token, error) {
	b, err := t.readByte()
	if err != nil {
		if err == io.EOF {
			return token{kind: tokEOF, pos: Position{t.pos, t.pos}}, nil
		}
		return token{}, err
	}
	if b != '<' {
		start := t.pos - 1
		var sb strings.Builder
		sb.WriteByte(b)
		for {
			c, err := t.readByte()
			if err != nil {
				if err == io.EOF {
					break
				}
				return token{}, err
			}
			if c == '<' {
				t.unreadByte()
				break
			}
			sb.WriteByte(c)
		}
		return token{kind: tokText, data: DecodeEntities(sb.String()), pos: Position{start, t.pos}}, nil
	}
	start := t.pos - 1
	c, err := t.readByte()
	if err != nil {
		if err == io.EOF {
			t.issue("stray '<' at end of input", start, t.pos)
			return token{kind: tokText, data: "<", pos: Position{start, t.pos}}, nil
		}
		return token{}, err
	}
	switch {
	case c == '!':
		if err := t.skipDeclaration(start); err != nil {
			return token{}, err
		}
		return t.next()
	case c == '/':
		return t.scanEndTag(start)
	case isTagNameStart(c):
		return t.scanStartTag(start, c)
	default:
		t.issue("'<' not followed by tag, treated as text", start, start+1)
		return token{kind: tokText, data: "<", pos: Position{start, start + 1}}, nil
	}
}

// skipDeclaration 跳过注释与 <!...> 声明，注释不进入输出。
func (t *streamTokenizer) skipDeclaration(start int) error {
	// 判断是否为注释 <!--
	peek, err := t.br.Peek(2)
	isComment := err == nil && peek[0] == '-' && peek[1] == '-'
	if isComment {
		t.readByte()
		t.readByte()
	}
	prev2, prev1 := byte(0), byte(0)
	n := 0
	for {
		c, err := t.readByte()
		if err != nil {
			if err == io.EOF {
				t.issue("unterminated comment or declaration", start, t.pos)
				return nil
			}
			return err
		}
		n++
		if n > maxTagSize {
			t.issue("comment or declaration exceeds size cap, truncated", start, t.pos)
			return nil
		}
		if isComment {
			if prev2 == '-' && prev1 == '-' && c == '>' {
				return nil
			}
		} else if c == '>' {
			return nil
		}
		prev2, prev1 = prev1, c
	}
}

func (t *streamTokenizer) scanEndTag(start int) (token, error) {
	var name strings.Builder
	for {
		c, err := t.readByte()
		if err != nil {
			if err == io.EOF {
				t.issue("unterminated end tag", start, t.pos)
				return token{kind: tokEOF, pos: Position{t.pos, t.pos}}, nil
			}
			return token{}, err
		}
		if isTagNameChar(c) {
			name.WriteByte(c)
			continue
		}
		if c != '>' {
			// 跳过标签内剩余内容
			if err := t.skipToGT(start); err != nil {
				return token{}, err
			}
		}
		return token{kind: tokEnd, data: strings.ToLower(name.String()), pos: Position{start, t.pos}}, nil
	}
}

func (t *streamTokenizer) scanStartTag(start int, first byte) (token, error) {
	var name strings.Builder
	name.WriteByte(first)
	tok := token{kind: tokStart, pos: Position{Start: start}}
	nameDone := false
	for {
		c, err := t.readByte()
		if err != nil {
			if err == io.EOF {
				t.issue("unterminated start tag", start, t.pos)
				return token{kind: tokEOF, pos: Position{t.pos, t.pos}}, nil
			}
			return token{}, err
		}
		if t.pos-start > maxTagSize {
			t.issue("start tag exceeds size cap, treated as text", start, t.pos)
			return token{kind: tokText, data: "<", pos: Position{start, start + 1}}, nil
		}
		switch {
		case !nameDone && isTagNameChar(c):
			name.WriteByte(c)
		case c == '>':
			tok.data = strings.ToLower(name.String())
			tok.pos.End = t.pos
			return tok, nil
		case c == '/':
			// 可能是自闭合 />
			nc, err := t.readByte()
			if err != nil {
				if err == io.EOF {
					t.issue("unterminated start tag", start, t.pos)
					return token{kind: tokEOF, pos: Position{t.pos, t.pos}}, nil
				}
				return token{}, err
			}
			if nc == '>' {
				tok.data = strings.ToLower(name.String())
				tok.selfClosing = true
				tok.pos.End = t.pos
				return tok, nil
			}
			nameDone = true
		case isSpace(c):
			nameDone = true
		default:
			// 进入属性扫描：把已读字节交给 scanAttr
			nameDone = true
			tok.data = strings.ToLower(name.String())
			a, err := t.scanAttr(start, c)
			if err != nil {
				return token{}, err
			}
			if a.Key != "" {
				tok.attr = append(tok.attr, a)
			}
		}
	}
}

// scanAttr 从当前位置解析一个属性，首字节已读出。
func (t *streamTokenizer) scanAttr(tagStart int, first byte) (Attribute, error) {
	var key strings.Builder
	if !isSpace(first) && first != '/' && first != '>' {
		key.WriteByte(first)
	}
	// 读属性名
	for {
		c, err := t.readByte()
		if err != nil {
			if err == io.EOF {
				t.issue("unterminated attribute", tagStart, t.pos)
				return Attribute{Key: strings.ToLower(key.String())}, nil
			}
			return Attribute{}, err
		}
		if isSpace(c) || c == '=' || c == '>' || c == '/' {
			if c != '=' {
				// 跳过空白找 '='
				if c == '>' || c == '/' {
					t.unreadByte()
					return Attribute{Key: strings.ToLower(key.String())}, nil
				}
				// 空白：peek 看是否有 '='
				for {
					nc, err := t.readByte()
					if err != nil {
						return Attribute{Key: strings.ToLower(key.String())}, nil
					}
					if isSpace(nc) {
						continue
					}
					if nc == '=' {
						goto value
					}
					t.unreadByte()
					return Attribute{Key: strings.ToLower(key.String())}, nil
				}
			}
			goto value
		}
		key.WriteByte(c)
	}
value:
	// 跳过空白
	var c byte
	for {
		var err error
		c, err = t.readByte()
		if err != nil {
			return Attribute{Key: strings.ToLower(key.String())}, nil
		}
		if !isSpace(c) {
			break
		}
	}
	var val strings.Builder
	if c == '"' || c == '\'' {
		q := c
		for {
			nc, err := t.readByte()
			if err != nil {
				t.issue("unterminated attribute value", tagStart, t.pos)
				break
			}
			if nc == q {
				break
			}
			val.WriteByte(nc)
		}
	} else {
		val.WriteByte(c)
		for {
			nc, err := t.readByte()
			if err != nil {
				break
			}
			if isSpace(nc) || nc == '>' {
				t.unreadByte()
				break
			}
			val.WriteByte(nc)
		}
	}
	return Attribute{Key: strings.ToLower(key.String()), Val: DecodeEntities(val.String())}, nil
}

func (t *streamTokenizer) skipToGT(start int) error {
	for {
		c, err := t.readByte()
		if err != nil {
			if err == io.EOF {
				t.issue("unterminated tag", start, t.pos)
				return nil
			}
			return err
		}
		if c == '>' {
			return nil
		}
	}
}

// ---- 流式净化 ----

type frame struct {
	name    string
	emitted bool
	dropped bool
	pos     Position
}

func streamSanitize(tz *streamTokenizer, w *bufio.Writer, p *Policy, res *StreamResult) error {
	var stack []frame
	dropCount := 0
	scope := p.IdentScope
	if scope == "" {
		scope = p.Version
	}
	_ = scope

	closeFrame := func(f frame) {
		if f.emitted {
			w.WriteString("</")
			w.WriteString(f.name)
			w.WriteByte('>')
		}
		if f.dropped {
			dropCount--
		}
	}

	for {
		tok, err := tz.next()
		if err != nil {
			return err
		}
		switch tok.kind {
		case tokEOF:
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].emitted {
					tz.issue("unclosed element <"+stack[i].name+"> implicitly closed at EOF", stack[i].pos.Start, stack[i].pos.End)
				}
				closeFrame(stack[i])
			}
			return nil
		case tokText:
			if dropCount > 0 {
				continue
			}
			w.WriteString(textEscaper.Replace(tok.data))
		case tokStart:
			name := tok.data
			// 隐式闭合规则
			if name == "li" {
				for len(stack) > 0 && stack[len(stack)-1].name == "li" {
					tz.issue("element <li> implicitly closed by new <li>", tok.pos.Start, tok.pos.End)
					closeFrame(stack[len(stack)-1])
					stack = stack[:len(stack)-1]
				}
			}
			if closesP[name] && len(stack) > 0 && stack[len(stack)-1].name == "p" {
				tz.issue("element <p> implicitly closed by <"+name+">", tok.pos.Start, tok.pos.End)
				closeFrame(stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			if dropCount > 0 {
				if !voidElements[name] && !tok.selfClosing {
					stack = append(stack, frame{name: name, dropped: true, pos: tok.pos})
					dropCount++
				}
				continue
			}
			f := frame{name: name, pos: tok.pos}
			switch {
			case p.DropElements[name]:
				f.dropped = true
			case !p.Elements[name]:
				// unwrap：不输出标签，保留子内容
			default:
				f.emitted = true
				el := &Node{Type: ElementNode, Data: name, Attr: tok.attr}
				el.Attr = p.sanitizeAttrs(el)
				writeOpenTag(w, el, voidElements[name] || tok.selfClosing)
			}
			if voidElements[name] || tok.selfClosing {
				continue
			}
			if f.dropped {
				dropCount++
			}
			stack = append(stack, f)
		case tokEnd:
			name := tok.data
			idx := -1
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].name == name {
					idx = i
					break
				}
			}
			if idx < 0 {
				tz.issue("unmatched end tag </"+name+"> ignored", tok.pos.Start, tok.pos.End)
				continue
			}
			for i := len(stack) - 1; i >= idx; i-- {
				if i != idx && stack[i].emitted {
					tz.issue("element <"+stack[i].name+"> implicitly closed by </"+name+">", tok.pos.Start, tok.pos.End)
				}
				closeFrame(stack[i])
			}
			stack = stack[:idx]
		}
	}
}

// writeOpenTag 输出一个开始标签（或自闭合标签）。
func writeOpenTag(w *bufio.Writer, el *Node, selfClosing bool) {
	w.WriteByte('<')
	w.WriteString(el.Data)
	for _, a := range el.Attr {
		w.WriteByte(' ')
		w.WriteString(a.Key)
		w.WriteString(`="`)
		w.WriteString(attrEscaper.Replace(a.Val))
		w.WriteByte('"')
	}
	if selfClosing {
		w.WriteString("/>")
		return
	}
	w.WriteByte('>')
}
