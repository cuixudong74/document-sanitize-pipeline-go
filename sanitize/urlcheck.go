package sanitize

import (
	"strconv"
	"strings"
)

// CheckURL 依据策略校验链接或资源地址，返回净化后的地址与是否保留。
//
// 判定规则（确定且可解释）：
//  1. 先做 HTML 实体解码并剔除空白与控制字符——浏览器在解析 URL 前也会这样做，
//     不处理会让 "javascript&#58;" 或 "java\tscript:" 之类写法绕过检查；
//  2. 含 scheme（"xxx:" 前缀）的绝对地址：scheme 必须在策略白名单内；
//  3. 协议相对地址（"//host/path"）与相对地址：仅当策略允许相对地址时保留；
//  4. 其余形态（空串、无法解析的畸形值）一律清除。
func CheckURL(raw string, p Policy) (string, bool) {
	cleaned := cleanURL(raw)
	if cleaned == "" {
		return "", false
	}
	if i := schemeEnd(cleaned); i >= 0 {
		scheme := lowerASCII(cleaned[:i])
		if !p.URLSchemes[scheme] {
			return "", false
		}
		return cleaned, true
	}
	// 无 scheme：相对地址或协议相对地址。
	if p.AllowRelativeURL {
		return cleaned, true
	}
	return "", false
}

// schemeEnd 返回 URL 中 scheme 分隔符 ":" 的位置；无合法 scheme 时返回 -1。
// 合法 scheme 以字母开头，后随字母、数字、"+"、"-"、"."。
func schemeEnd(s string) int {
	if s == "" || !isASCIILetter(s[0]) {
		return -1
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':':
			return i
		case isASCIILetter(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.':
		default:
			return -1
		}
	}
	return -1
}

// cleanURL 做实体解码并剔除空白与控制字符。
func cleanURL(raw string) string {
	decoded := decodeEntities(raw)
	var b strings.Builder
	b.Grow(len(decoded))
	for _, r := range decoded {
		if r <= 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// namedEntities 是安全判定所需的最小命名实体表。
var namedEntities = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'',
	"colon": ':', "sol": '/', "Tab": '\t', "NewLine": '\n',
}

// decodeEntities 解码数字字符引用与安全相关的命名实体。
func decodeEntities(s string) string {
	if !strings.ContainsRune(s, '&') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		semi := strings.IndexByte(s[i:], ';')
		if semi < 0 || semi > 12 {
			b.WriteByte(s[i])
			i++
			continue
		}
		body := s[i+1 : i+semi]
		if r, ok := decodeEntity(body); ok {
			b.WriteRune(r)
			i += semi + 1
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

func decodeEntity(body string) (rune, bool) {
	if body == "" {
		return 0, false
	}
	if body[0] == '#' {
		num := body[1:]
		base := 10
		if len(num) > 0 && (num[0] == 'x' || num[0] == 'X') {
			num = num[1:]
			base = 16
		}
		if num == "" {
			return 0, false
		}
		n, err := strconv.ParseInt(num, base, 32)
		if err != nil || n <= 0 || n > 0x10FFFF {
			return 0, false
		}
		return rune(n), true
	}
	r, ok := namedEntities[body]
	return r, ok
}
