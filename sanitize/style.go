package sanitize

import (
	"strings"
)

// SanitizeStyle 按策略允许的属性逐一筛选内联样式声明。
//
// 规则（确定且可复现）：
//   - 声明按 ";" 切分，属性名小写化后必须在策略白名单内；
//   - 取值先做实体解码，含 expression()、javascript:/vbscript:、@import
//     等危险形态的整条声明剥离；
//   - url(...) 取值复用 CheckURL 的协议校验，不通过则剥离该声明；
//   - 同名属性后者覆盖前者，输出按属性名排序——同一输入多次净化结果完全一致。
func SanitizeStyle(style string, p Policy) string {
	if style == "" {
		return ""
	}
	kept := map[string]string{}
	for _, decl := range strings.Split(style, ";") {
		name, value, ok := splitDecl(decl)
		if !ok {
			continue
		}
		if !p.CSSProperties[name] {
			continue
		}
		if !safeCSSValue(value, p) {
			continue
		}
		kept[name] = value
	}
	if len(kept) == 0 {
		return ""
	}
	names := sortedKeys(kept)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(n)
		b.WriteString(": ")
		b.WriteString(kept[n])
	}
	return b.String()
}

// splitDecl 把一条声明切为属性名与取值。
func splitDecl(decl string) (name, value string, ok bool) {
	i := strings.IndexByte(decl, ':')
	if i < 0 {
		return "", "", false
	}
	name = lowerASCII(strings.TrimSpace(decl[:i]))
	value = strings.TrimSpace(decl[i+1:])
	if name == "" || value == "" {
		return "", "", false
	}
	return name, value, true
}

// safeCSSValue 判断样式取值是否安全。
func safeCSSValue(value string, p Policy) bool {
	decoded := decodeEntities(value)
	lower := lowerASCII(decoded)
	// 压缩空白后检查危险关键字，防止 "expre\\ssion" 之外的空白穿插绕过。
	compact := strings.Map(func(r rune) rune {
		if r <= 0x20 {
			return -1
		}
		return r
	}, lower)
	for _, bad := range []string{"expression(", "javascript:", "vbscript:", "@import", "behavior:", "-moz-binding"} {
		if strings.Contains(compact, bad) {
			return false
		}
	}
	// 逐一校验 url(...) 引用。
	rest := decoded
	for {
		i := indexFold(rest, "url(")
		if i < 0 {
			return true
		}
		inner := rest[i+4:]
		end := strings.IndexByte(inner, ')')
		if end < 0 {
			return false // 未闭合的 url(，保守剥离
		}
		raw := strings.Trim(strings.TrimSpace(inner[:end]), `"'`)
		if _, ok := CheckURL(raw, p); !ok {
			return false
		}
		rest = inner[end+1:]
	}
}

// indexFold 大小写不敏感地查找子串。
func indexFold(s, sub string) int {
	ls, lsub := len(s), len(sub)
	for i := 0; i+lsub <= ls; i++ {
		if equalFoldBytes([]byte(s[i:i+lsub]), []byte(sub)) {
			return i
		}
	}
	return -1
}

// RewriteClass 按稳定规则重写类名列表：
// 每个类名加上策略前缀，非法字符替换为 "-"，空结果丢弃。
// 同一输入在同一策略下结果恒定，且不会与宿主页面类名冲突。
func RewriteClass(class string, p Policy) string {
	fields := strings.Fields(class)
	if len(fields) == 0 {
		return ""
	}
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		rw := p.ClassPrefix + sanitizeIdent(f)
		if rw == p.ClassPrefix || seen[rw] {
			continue
		}
		seen[rw] = true
		out = append(out, rw)
	}
	return strings.Join(out, " ")
}

// RewriteID 按与类名相同的稳定规则重写 id。
func RewriteID(id string, p Policy) string {
	s := sanitizeIdent(strings.TrimSpace(id))
	if s == "" {
		return ""
	}
	return p.ClassPrefix + s
}

// sanitizeIdent 保留标识符中的安全字符，其余替换为 "-"。
func sanitizeIdent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
