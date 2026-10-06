package sanitize

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// identPrefix 是所有重写后标识的统一前缀，避免与宿主页面冲突。
const identPrefix = "dz-"

// RewriteIdent 按稳定规则重写类名与 id。
//
// 规则：输出 = "dz-" + FNV-1a(scope + "/" + name) 的十六进制。
// 同一 (scope, name) 在任何进程、任何时刻都得到同一结果，
// 因此同一份输入多次净化的结果完全一致；不同文档作用域之间不会撞名。
func RewriteIdent(scope, name string) string {
	h := fnv.New64a()
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(name))
	return fmt.Sprintf("%s%016x", identPrefix, h.Sum64())
}

// RewriteClassList 重写 class 属性值中的每个类名，保持顺序、去重。
func RewriteClassList(scope, classAttr string) string {
	seen := map[string]bool{}
	var out []string
	for _, name := range strings.Fields(classAttr) {
		rw := RewriteIdent(scope, name)
		if !seen[rw] {
			seen[rw] = true
			out = append(out, rw)
		}
	}
	return strings.Join(out, " ")
}
