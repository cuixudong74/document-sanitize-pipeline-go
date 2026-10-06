package sanitize

// NodeType 区分中间结构中的节点种类。
type NodeType int

const (
	DocumentNode NodeType = iota
	ElementNode
	TextNode
	CommentNode
)

// Position 记录节点在原始输入中的字节偏移范围，用于定位问题位置。
type Position struct {
	Start int
	End   int
}

// Attribute 是元素上的一个属性。
type Attribute struct {
	Key string
	Val string
}

// Node 是解析后的统一中间结构节点。
type Node struct {
	Type     NodeType
	Data     string // 元素标签名或文本内容
	Attr     []Attribute
	Children []*Node
	Parent   *Node
	Pos      Position
}

// AppendChild 将子节点挂到父节点下。
func (n *Node) AppendChild(c *Node) {
	c.Parent = n
	n.Children = append(n.Children, c)
}
