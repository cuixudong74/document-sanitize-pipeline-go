// Package sanitize 提供面向富文本导入的内容净化与规范化能力。
//
// 整条链路：解析（容错） -> 白名单过滤 -> URL 校验 -> 样式/类名规范化 -> 规范化输出。
// 全部在本进程内完成，不依赖外部服务，结果可本地稳定复现。
package sanitize

import "fmt"

// NodeKind 表示中间结构中的节点类别。
type NodeKind int

const (
	KindDocument NodeKind = iota // 根节点
	KindElement                  // 元素节点
	KindText                     // 文本节点
	KindComment                  // 注释节点（默认会被净化剥离）
	KindDoctype                  // 文档类型节点
)

// Node 是统一中间结构（DOM）中的节点。
type Node struct {
	Kind     NodeKind
	Tag      string // 元素标签名（小写），仅 KindElement 有效
	Attrs    []Attr // 属性，仅 KindElement 有效
	Data     string // 文本/注释内容
	Children []*Node
	Parent   *Node
	// Offset 是该节点在原始输入中的起始字节偏移，用于定位问题位置。
	Offset int
}

// Attr 是一个元素属性。
type Attr struct {
	Key string
	Val string
}

// Issue 描述解析或净化过程中发现并恢复的一个问题。
type Issue struct {
	Kind    IssueKind
	Offset  int // 字节偏移
	Line    int // 1 起始行号
	Column  int // 1 起始列号
	Message string
}

// IssueKind 区分问题类别。
type IssueKind int

const (
	IssueUnclosedTag     IssueKind = iota // 标签未闭合，已自动补全
	IssueStrayEndTag                      // 多余的结束标签，已忽略
	IssueIllegalNesting                   // 非法嵌套，已重排
	IssueBadTag                           // 畸形标签，已按文本处理
	IssueStrippedElement                  // 元素不在白名单，已剥离
	IssueStrippedAttr                     // 属性被策略剥离
	IssueSanitizedURL                     // URL 被清除或替换
	IssueSanitizedStyle                   // 样式声明被剥离
)

func (k IssueKind) String() string {
	switch k {
	case IssueUnclosedTag:
		return "unclosed-tag"
	case IssueStrayEndTag:
		return "stray-end-tag"
	case IssueIllegalNesting:
		return "illegal-nesting"
	case IssueBadTag:
		return "bad-tag"
	case IssueStrippedElement:
		return "stripped-element"
	case IssueStrippedAttr:
		return "stripped-attr"
	case IssueSanitizedURL:
		return "sanitized-url"
	case IssueSanitizedStyle:
		return "sanitized-style"
	}
	return "unknown"
}

// ErrKind 是可区分、可恢复的错误类别。
type ErrKind int

const (
	ErrKindParse    ErrKind = iota // 输入无法被解析（超过容错能力）
	ErrKindPolicy                  // 策略拒绝（如文档为空或含被禁内容根）
	ErrKindTooLarge                // 超过配置的大小/节点上限
)

func (k ErrKind) String() string {
	switch k {
	case ErrKindParse:
		return "parse"
	case ErrKindPolicy:
		return "policy"
	case ErrKindTooLarge:
		return "too-large"
	}
	return "unknown"
}

// Error 是携带类别的错误，调用方可按类别区分处理并恢复。
type Error struct {
	Kind    ErrKind
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("sanitize: %s error: %s", e.Kind, e.Message) }
