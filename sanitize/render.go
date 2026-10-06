package sanitize

import (
	"io"
	"strings"
)

var textEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
)

var attrEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
)

// Render 把中间结构序列化回标记文本。输出是确定性的：
// 同一棵树多次渲染结果完全一致。
func Render(w io.Writer, n *Node) error {
	var sb strings.Builder
	renderNode(&sb, n)
	_, err := io.WriteString(w, sb.String())
	return err
}

// RenderString 是 Render 的便捷封装。
func RenderString(n *Node) string {
	var sb strings.Builder
	renderNode(&sb, n)
	return sb.String()
}

func renderNode(sb *strings.Builder, n *Node) {
	switch n.Type {
	case DocumentNode:
		for _, c := range n.Children {
			renderNode(sb, c)
		}
	case TextNode:
		sb.WriteString(textEscaper.Replace(n.Data))
	case CommentNode:
		// 注释不输出，避免夹带条件注释等历史包袱
	case ElementNode:
		sb.WriteByte('<')
		sb.WriteString(n.Data)
		for _, a := range n.Attr {
			sb.WriteByte(' ')
			sb.WriteString(a.Key)
			sb.WriteString(`="`)
			sb.WriteString(attrEscaper.Replace(a.Val))
			sb.WriteByte('"')
		}
		if voidElements[n.Data] {
			sb.WriteString("/>")
			return
		}
		sb.WriteByte('>')
		for _, c := range n.Children {
			renderNode(sb, c)
		}
		sb.WriteString("</")
		sb.WriteString(n.Data)
		sb.WriteByte('>')
	}
}
