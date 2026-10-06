package sanitize

import (
	"sort"
	"strings"
)

// dangerousValueSubstrings 出现在样式值中即整条声明被拒绝，
// 覆盖 expression()、-moz-binding、行为绑定等历史与现行攻击面。
var dangerousValueSubstrings = []string{
	"expression(", "-moz-binding", "behavior:", "@import", "javascript:", "vbscript:",
}

// SanitizeStyle 按允许的属性白名单筛选内联样式。
//
// 解析容忍畸形声明（缺少冒号、值为空等），坏声明被丢弃而不影响其余声明。
// 输出按属性名排序并统一为 "prop: value; " 形式，保证同一输入多次
// 净化的结果完全一致。
func SanitizeStyle(css string, allowed map[string]bool) string {
	decls := parseDeclarations(css)
	kept := map[string]string{}
	for _, d := range decls {
		prop, val := d[0], d[1]
		if !allowed[prop] {
			continue
		}
		if !safeValue(val) {
			continue
		}
		kept[prop] = val // 同名属性后者覆盖前者，结果确定
	}
	if len(kept) == 0 {
		return ""
	}
	props := make([]string, 0, len(kept))
	for p := range kept {
		props = append(props, p)
	}
	sort.Strings(props)
	var sb strings.Builder
	for _, p := range props {
		sb.WriteString(p)
		sb.WriteString(": ")
		sb.WriteString(kept[p])
		sb.WriteString("; ")
	}
	return sb.String()
}

// parseDeclarations 把样式文本拆成 [属性, 值] 对，属性名小写化。
func parseDeclarations(css string) [][2]string {
	var out [][2]string
	for _, chunk := range strings.Split(css, ";") {
		i := strings.IndexByte(chunk, ':')
		if i < 0 {
			continue
		}
		prop := strings.ToLower(strings.TrimSpace(chunk[:i]))
		val := strings.TrimSpace(chunk[i+1:])
		if prop == "" || val == "" {
			continue
		}
		out = append(out, [2]string{prop, val})
	}
	return out
}

// safeValue 检查样式值是否安全；url() 内的地址按 URL 规则校验。
func safeValue(val string) bool {
	lower := strings.ToLower(val)
	for _, bad := range dangerousValueSubstrings {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	// 校验 url(...) 引用
	rest := lower
	for {
		i := strings.Index(rest, "url(")
		if i < 0 {
			return true
		}
		rest = rest[i+4:]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return false
		}
		u := strings.Trim(strings.TrimSpace(rest[:end]), `"'`)
		if _, ok := CheckURL(u, true); !ok {
			return false
		}
		rest = rest[end+1:]
	}
}
