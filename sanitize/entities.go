package sanitize

import (
	"strings"
	"unicode/utf8"
)

// namedEntities 是解析时识别的命名实体；未知实体原样保留。
var namedEntities = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'', "nbsp':": 0,
}

func init() {
	// nbsp 单独设置，避免上面字面量笔误
	delete(namedEntities, "nbsp':")
	namedEntities["nbsp"] = ' '
}

// DecodeEntities 把文本中的 HTML 实体解码为字符。
// 树中保存解码后的文本，渲染时重新转义，保证往返一致。
func DecodeEntities(s string) string {
	if !strings.ContainsRune(s, '&') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '&' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		semi := strings.IndexByte(s[i:], ';')
		if semi < 0 || semi > 32 {
			sb.WriteByte('&')
			i++
			continue
		}
		ent := s[i+1 : i+semi]
		if r, ok := decodeEntity(ent); ok {
			sb.WriteRune(r)
			i += semi + 1
		} else {
			sb.WriteByte('&')
			i++
		}
	}
	return sb.String()
}

func decodeEntity(ent string) (rune, bool) {
	if ent == "" {
		return 0, false
	}
	if ent[0] == '#' {
		var n int
		rest := ent[1:]
		base := 10
		if len(rest) > 0 && (rest[0] == 'x' || rest[0] == 'X') {
			base = 16
			rest = rest[1:]
		}
		if rest == "" {
			return 0, false
		}
		for _, c := range rest {
			var d int
			switch {
			case c >= '0' && c <= '9':
				d = int(c - '0')
			case base == 16 && c >= 'a' && c <= 'f':
				d = int(c-'a') + 10
			case base == 16 && c >= 'A' && c <= 'F':
				d = int(c-'A') + 10
			default:
				return 0, false
			}
			n = n*base + d
			if n > utf8.MaxRune {
				return 0, false
			}
		}
		if n == 0 || !utf8.ValidRune(rune(n)) {
			return utf8.RuneError, true
		}
		return rune(n), true
	}
	if r, ok := namedEntities[ent]; ok {
		return r, true
	}
	return 0, false
}
