package sanitize

import (
	"bytes"
	"context"
	"sort"
	"sync"
)

// Status 区分单篇导入结果。
type Status int

const (
	StatusOK Status = iota
	StatusFailed
)

func (s Status) String() string {
	if s == StatusOK {
		return "ok"
	}
	return "failed"
}

// Record 是一篇已入库文档及其策略版本。
// 入库后内容不可变：新策略不会改写历史文档。
type Record struct {
	ID            string
	Content       string
	PolicyVersion string
	Issues        []ParseIssue
}

// Result 描述批量导入中单篇文档的结果。
type Result struct {
	ID     string
	Status Status
	Issues []ParseIssue
	Err    *Error
}

// Store 管理文档的幂等导入与按策略版本读取，并发安全。
type Store struct {
	mu       sync.RWMutex
	policies map[string]*Policy
	records  map[string]Record
	limits   Limits
}

// NewStore 创建一个按版本注册策略的存储。
func NewStore(policies ...*Policy) *Store {
	s := &Store{
		policies: map[string]*Policy{},
		records:  map[string]Record{},
		limits:   Limits{MaxBytes: DefaultMaxBytes},
	}
	for _, p := range policies {
		s.policies[p.Version] = p
	}
	return s
}

// SetLimits 配置单篇文档的处理上限。
func (s *Store) SetLimits(l Limits) { s.limits = l }

// Import 幂等导入一篇文档。
//
// 同一 (id, content, policyVersion) 重复导入是空操作，不产生重复副作用；
// 同一 id 不同内容会确定性覆盖。同一输入与策略在并发请求下结果一致。
func (s *Store) Import(ctx context.Context, id string, content []byte, policyVersion string) Result {
	s.mu.RLock()
	p, ok := s.policies[policyVersion]
	s.mu.RUnlock()
	if !ok {
		return Result{ID: id, Status: StatusFailed, Err: &Error{
			Kind: ErrKindPolicy, Message: "unknown policy version: " + policyVersion}}
	}
	if err := ctx.Err(); err != nil {
		return Result{ID: id, Status: StatusFailed, Err: &Error{
			Kind: ErrKindPolicy, Message: "import canceled: " + err.Error()}}
	}

	var buf bytes.Buffer
	sres, err := SanitizeStream(bytes.NewReader(content), &buf, p, s.limits)
	if err != nil {
		if se, ok := err.(*Error); ok {
			return Result{ID: id, Status: StatusFailed, Err: se}
		}
		return Result{ID: id, Status: StatusFailed, Err: &Error{Kind: ErrKindParse, Message: err.Error()}}
	}
	out := buf.String()
	// 策略级拒绝：输入有实质内容但净化后为空
	if out == "" && len(bytes.TrimSpace(content)) > 0 {
		return Result{ID: id, Status: StatusFailed, Err: &Error{
			Kind: ErrKindPolicy, Message: "document rejected by policy: no allowed content"}}
	}

	rec := Record{ID: id, Content: out, PolicyVersion: policyVersion, Issues: sres.Issues}
	s.mu.Lock()
	if old, exists := s.records[id]; exists && old.Content == rec.Content && old.PolicyVersion == rec.PolicyVersion {
		s.mu.Unlock()
		return Result{ID: id, Status: StatusOK, Issues: sres.Issues} // 幂等空操作
	}
	s.records[id] = rec
	s.mu.Unlock()
	return Result{ID: id, Status: StatusOK, Issues: sres.Issues}
}

// ImportBatch 批量导入，单篇失败不影响同批其他文档。
// 结果按文档 ID 排序返回，成功与失败都可查询。
func (s *Store) ImportBatch(ctx context.Context, docs map[string][]byte, policyVersion string) []Result {
	ids := make([]string, 0, len(docs))
	for id := range docs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	results := make([]Result, 0, len(ids))
	for _, id := range ids {
		results = append(results, s.Import(ctx, id, docs[id], policyVersion))
	}
	return results
}

// Get 按入库时的策略版本读取文档。
func (s *Store) Get(id string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	return rec, ok
}
