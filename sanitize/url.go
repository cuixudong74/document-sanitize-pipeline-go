package sanitize

import "strings"

// allowedSchemes 是允许出现在输出中的 URL 协议。
var allowedSchemes = map[string]bool{
	"http":   true,
	"https":  true,
	"mailto": true,
	"tel":    true,
}

// CheckURL 校验链接或资源地址，返回规范化后的地址与是否放行。
//
// 判定规则（确定且可解释）：
//  1. 先剥离首尾空白与所有控制字符（浏览器会忽略 "java\tscript:" 中的制表符，
//     因此校验前必须做同样的归一化）。
//  2. 若第一个 ':' 出现在任何 '/', '?', '#' 之前，则前缀视为协议；
//     协议必须在白名单内（不区分大小写），否则拒绝。
//  3. 没有协议的地址视为相对地址，仅当 allowRelative 为真时放行。
//  4. 以 "//" 开头的协议相对地址一律拒绝：其实际协议取决于页面环境，
//     无法在本地确定地判定。
func CheckURL(raw string, allowRelative bool) (string, bool) {
	cleaned := stripControlsAndSpace(raw)
	if cleaned == "" {
		return "", false
	}
	if strings.HasPrefix(cleaned, "//") {
		return "", false
	}
	// 以 ':' 开头不是合法相对地址（相对引用首段不得含冒号）
	if strings.HasPrefix(cleaned, ":") {
		return "", false
	}
	if i := schemeEnd(cleaned); i >= 0 {
		scheme := strings.ToLower(cleaned[:i])
		if !allowedSchemes[scheme] {
			return "", false
		}
		return cleaned, true
	}
	if !allowRelative {
		return "", false
	}
	return cleaned, true
}

// schemeEnd 返回协议分隔符 ':' 的下标；没有协议时返回 -1。
func schemeEnd(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':':
			if i == 0 {
				return -1
			}
			return i
		case c == '/' || c == '?' || c == '#':
			return -1
		case isSchemeChar(c):
		default:
			return -1
		}
	}
	return -1
}

func isSchemeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
}

// stripControlsAndSpace 去除首尾空白以及字符串内所有 ASCII 控制字符，
// 与浏览器对 URL 的容错行为保持一致，防止 "java\tscript:" 之类的绕过。
func stripControlsAndSpace(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
