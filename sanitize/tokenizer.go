package sanitize

import (
	"bytes"
	"io"
)

// tokenKind 是词法产物的类别。
type tokenKind int

const (
	tokEOF tokenKind = iota
	tokText
	tokStartTag
	tokEndTag
	tokComment
	tokDoctype
)

// token 是词法层的产物，带原始输入中的位置信息。
type token struct {
	kind      tokenKind
	data      string // 标签名（小写）或文本/注释内容
	attrs     []Attr // 仅 tokStartTag
	selfClose bool   // 以 "/>" 结尾
	offset    int    // 起始字节偏移
	line, col int    // 1 起始行列
	issue     *Issue // 词法层即发现的问题（如畸形标签），可为空
}

// rawTextTags 的内容按原始文本处理，直到匹配的结束标签。
var rawTextTags = map[string]bool{
	"script": true, "style": true, "textarea": true, "title": true,
}

// tokenizer 是容错的手写词法分析器：
//   - 畸形标签（如 "< div"、"<3"）按纯文本处理并记录问题；
//   - 未闭合的标签（输入结束仍无 ">"）按纯文本处理并记录问题；
//   - 任何单处畸形都不会中断整体扫描。
type tokenizer struct {
	buf []byte // 输入（流式模式下为超限即报错的有界缓冲）
	pos int
	// rawTag 非空时处于 raw text 模式，等待 </rawTag>。
	rawTag string
	// pending 是已扫描待取走的 token。
	pending *token
}

// limitReader 在读取超过上限时返回 errTooLargeInput。
type limitReader struct {
	r     io.Reader
	limit int
	read  int
}

var errTooLargeInput = &Error{Kind: ErrKindTooLarge, Message: "input exceeds MaxBytes limit"}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.read >= l.limit {
		// 已到达上限：探测底层是否还有数据，有则超限，否则正常结束。
		var one [1]byte
		n, err := l.r.Read(one[:])
		if n > 0 {
			return 0, errTooLargeInput
		}
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	if remain := l.limit - l.read; len(p) > remain {
		p = p[:remain]
	}
	n, err := l.r.Read(p)
	l.read += n
	return n, err
}

func newTokenizer(input []byte) *tokenizer {
	return &tokenizer{buf: input}
}

// newStreamTokenizer 以流式方式读取输入，读取量超过 lim.MaxBytes 即报错，
// 不会把超限输入全部载入内存。
func newStreamTokenizer(r io.Reader, lim Limits) (*tokenizer, error) {
	lim = lim.withDefaults()
	buf, err := io.ReadAll(&limitReader{r: r, limit: lim.MaxBytes})
	if err != nil {
		return nil, err
	}
	return &tokenizer{buf: buf}, nil
}

// lineCol 计算偏移处的 1 起始行列号。
func (t *tokenizer) lineCol(offset int) (line, col int) {
	line, col = 1, 1
	for i := 0; i < offset && i < len(t.buf); i++ {
		if t.buf[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isTagNameChar(c byte) bool {
	return isASCIILetter(c) || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// next 返回下一个 token，任何畸形都被局部恢复。
func (t *tokenizer) next() token {
	if t.pending != nil {
		tok := *t.pending
		t.pending = nil
		return tok
	}
	if t.pos >= len(t.buf) {
		return token{kind: tokEOF, offset: t.pos}
	}
	if t.rawTag != "" {
		return t.scanRawText()
	}
	start := t.pos
	if t.buf[t.pos] == '<' && t.pos+1 < len(t.buf) {
		switch {
		case isASCIILetter(t.buf[t.pos+1]):
			return t.scanTag(start)
		case t.buf[t.pos+1] == '/':
			return t.scanEndTag(start)
		case t.buf[t.pos+1] == '!':
			return t.scanMarkup(start)
		case t.buf[t.pos+1] == '?':
			// "<?...>" 按伪注释处理，跳过。
			return t.scanBogusComment(start)
		}
	}
	// 普通文本（含无法识别为标签的 "<"）。
	return t.scanText(start)
}

// scanText 扫描到下一个 "<" 或输入结束。
func (t *tokenizer) scanText(start int) token {
	i := start + 1
	for i < len(t.buf) && t.buf[i] != '<' {
		i++
	}
	t.pos = i
	line, col := t.lineCol(start)
	return token{kind: tokText, data: string(t.buf[start:i]), offset: start, line: line, col: col}
}

// scanRawText 在 raw text 元素内扫描到匹配的结束标签。
func (t *tokenizer) scanRawText() token {
	start := t.pos
	closing := "</" + t.rawTag
	rest := t.buf[t.pos:]
	idx := indexCloseTag(rest, closing)
	if idx < 0 {
		// 没有匹配的结束标签：剩余全部按文本，由树构建层报告未闭合。
		t.pos = len(t.buf)
		line, col := t.lineCol(start)
		return token{kind: tokText, data: string(t.buf[start:]), offset: start, line: line, col: col}
	}
	if idx == 0 {
		// 紧邻结束标签：退出 raw text 模式，按正常流程扫描结束标签。
		t.rawTag = ""
		return t.next()
	}
	t.pos = start + idx
	line, col := t.lineCol(start)
	return token{kind: tokText, data: string(t.buf[start : start+idx]), offset: start, line: line, col: col}
}

// indexCloseTag 在 s 中查找大小写不敏感的结束标签（后随空白、"/" 或 ">"）。
func indexCloseTag(s []byte, closing string) int {
	for i := 0; i+len(closing) <= len(s); i++ {
		if equalFoldBytes(s[i:i+len(closing)], []byte(closing)) {
			j := i + len(closing)
			if j >= len(s) || s[j] == '>' || s[j] == '/' || isSpace(s[j]) {
				return i
			}
		}
	}
	return -1
}

func equalFoldBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// scanTag 扫描开始标签，容忍畸形属性。
func (t *tokenizer) scanTag(start int) token {
	i := start + 1
	nameStart := i
	for i < len(t.buf) && isTagNameChar(t.buf[i]) {
		i++
	}
	name := lowerASCII(string(t.buf[nameStart:i]))
	tok := token{kind: tokStartTag, data: name, offset: start}
	tok.line, tok.col = t.lineCol(start)

	// 扫描属性直到 ">" 或 "/>"。
	for i < len(t.buf) {
		for i < len(t.buf) && isSpace(t.buf[i]) {
			i++
		}
		if i >= len(t.buf) {
			break
		}
		if t.buf[i] == '>' {
			i++
			t.pos = i
			t.afterStartTag(&tok)
			return tok
		}
		if t.buf[i] == '/' && i+1 < len(t.buf) && t.buf[i+1] == '>' {
			i += 2
			tok.selfClose = true
			t.pos = i
			t.afterStartTag(&tok)
			return tok
		}
		attr, ni := t.scanAttr(i)
		i = ni
		if attr.Key != "" {
			tok.attrs = append(tok.attrs, attr)
		}
	}
	// 输入结束仍未闭合标签：整段按文本处理。
	line, col := t.lineCol(start)
	t.pos = len(t.buf)
	return token{
		kind: tokText, data: string(t.buf[start:]), offset: start, line: line, col: col,
		issue: &Issue{Kind: IssueBadTag, Offset: start, Line: line, Column: col,
			Message: "unterminated tag treated as text"},
	}
}

// afterStartTag 在进入 raw text 元素时切换模式。
func (t *tokenizer) afterStartTag(tok *token) {
	if rawTextTags[tok.data] && !tok.selfClose {
		t.rawTag = tok.data
	}
}

// scanAttr 从位置 i 扫描一个属性，返回属性与扫描结束位置。
func (t *tokenizer) scanAttr(i int) (Attr, int) {
	start := i
	for i < len(t.buf) && !isSpace(t.buf[i]) && t.buf[i] != '=' && t.buf[i] != '>' && t.buf[i] != '/' {
		i++
	}
	if i < len(t.buf) && t.buf[i] == '/' && i+1 < len(t.buf) && t.buf[i+1] != '>' {
		// 属性名中的孤立 "/"，跳过。
		i++
	}
	key := lowerASCII(string(t.buf[start:i]))
	for i < len(t.buf) && isSpace(t.buf[i]) {
		i++
	}
	if i >= len(t.buf) || t.buf[i] != '=' {
		return Attr{Key: key}, i
	}
	i++ // 跳过 '='
	for i < len(t.buf) && isSpace(t.buf[i]) {
		i++
	}
	if i >= len(t.buf) {
		return Attr{Key: key}, i
	}
	var val []byte
	if t.buf[i] == '"' || t.buf[i] == '\'' {
		quote := t.buf[i]
		i++
		vs := i
		for i < len(t.buf) && t.buf[i] != quote {
			i++
		}
		val = t.buf[vs:i]
		if i < len(t.buf) {
			i++ // 跳过收尾引号
		}
	} else {
		vs := i
		for i < len(t.buf) && !isSpace(t.buf[i]) && t.buf[i] != '>' {
			i++
		}
		val = t.buf[vs:i]
	}
	return Attr{Key: key, Val: string(val)}, i
}

// scanEndTag 扫描结束标签。
func (t *tokenizer) scanEndTag(start int) token {
	i := start + 2
	for i < len(t.buf) && isSpace(t.buf[i]) {
		i++
	}
	nameStart := i
	for i < len(t.buf) && isTagNameChar(t.buf[i]) {
		i++
	}
	name := lowerASCII(string(t.buf[nameStart:i]))
	// 丢弃结束标签上的任何属性，直到 ">"。
	for i < len(t.buf) && t.buf[i] != '>' {
		i++
	}
	if i < len(t.buf) {
		i++
	}
	line, col := t.lineCol(start)
	if name == "" {
		// "</>" 或 "</ >"：按文本处理。
		t.pos = i
		return token{kind: tokText, data: string(t.buf[start:i]), offset: start, line: line, col: col,
			issue: &Issue{Kind: IssueBadTag, Offset: start, Line: line, Column: col,
				Message: "empty end tag treated as text"}}
	}
	t.pos = i
	if t.rawTag == name {
		t.rawTag = ""
	}
	return token{kind: tokEndTag, data: name, offset: start, line: line, col: col}
}

// scanMarkup 处理 "<!" 开头：注释或 doctype。
func (t *tokenizer) scanMarkup(start int) token {
	line, col := t.lineCol(start)
	if bytes.HasPrefix(t.buf[start:], []byte("<!--")) {
		end := bytes.Index(t.buf[start+4:], []byte("-->"))
		if end < 0 {
			// 未闭合注释：剩余全部按注释，记录问题。
			t.pos = len(t.buf)
			return token{kind: tokComment, data: string(t.buf[start+4:]), offset: start, line: line, col: col,
				issue: &Issue{Kind: IssueBadTag, Offset: start, Line: line, Column: col,
					Message: "unterminated comment"}}
		}
		data := string(t.buf[start+4 : start+4+end])
		t.pos = start + 4 + end + 3
		return token{kind: tokComment, data: data, offset: start, line: line, col: col}
	}
	// doctype 或未知声明：跳到 ">"。
	i := start + 2
	for i < len(t.buf) && t.buf[i] != '>' {
		i++
	}
	if i < len(t.buf) {
		i++
	}
	t.pos = i
	return token{kind: tokDoctype, data: string(t.buf[start:i]), offset: start, line: line, col: col}
}

// scanBogusComment 处理 "<?...>"。
func (t *tokenizer) scanBogusComment(start int) token {
	line, col := t.lineCol(start)
	i := start + 2
	for i < len(t.buf) && t.buf[i] != '>' {
		i++
	}
	if i < len(t.buf) {
		i++
	}
	t.pos = i
	return token{kind: tokComment, data: string(t.buf[start+2 : max(start+2, i-1)]), offset: start, line: line, col: col}
}

func lowerASCII(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
