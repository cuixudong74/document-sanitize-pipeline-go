package sanitize

// Limits 描述单篇文档的处理上限，超过即返回可区分的 ErrKindTooLarge。
type Limits struct {
	// MaxBytes 是输入字节数上限，0 表示使用默认值。
	MaxBytes int
	// MaxNodes 是中间结构节点数上限，0 表示使用默认值。
	MaxNodes int
	// MaxDepth 是元素嵌套深度上限，0 表示使用默认值。
	MaxDepth int
}

// DefaultLimits 返回默认上限。
func DefaultLimits() Limits {
	return Limits{
		MaxBytes: 4 << 20, // 4 MiB
		MaxNodes: 100000,
		MaxDepth: 256,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxBytes > 0 {
		d.MaxBytes = l.MaxBytes
	}
	if l.MaxNodes > 0 {
		d.MaxNodes = l.MaxNodes
	}
	if l.MaxDepth > 0 {
		d.MaxDepth = l.MaxDepth
	}
	return d
}
