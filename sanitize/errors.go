package sanitize

import "fmt"

// ErrKind 区分失败原因：解析问题、策略拒绝、超过上限。
type ErrKind int

const (
	ErrKindParse ErrKind = iota
	ErrKindPolicy
	ErrKindTooLarge
)

func (k ErrKind) String() string {
	switch k {
	case ErrKindParse:
		return "parse"
	case ErrKindPolicy:
		return "policy"
	case ErrKindTooLarge:
		return "too_large"
	}
	return "unknown"
}

// Error 是可分类、可恢复的净化错误。
type Error struct {
	Kind    ErrKind
	Message string
	Pos     Position
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s error at [%d,%d): %s", e.Kind, e.Pos.Start, e.Pos.End, e.Message)
}
