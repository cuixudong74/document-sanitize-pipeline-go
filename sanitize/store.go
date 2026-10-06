package sanitize

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// Document 是一篇已入库的净化后文档。
type Document struct {
	// ID 由内容哈希与策略版本派生，同一（内容, 策略）对恒定，
	// 重复导入返回同一 ID，不产生重复副作用。
	ID            string
	HTML          string
	PolicyVersion string
	Issues        []Issue
}

// Store 是进程内文档存储，保证幂等导入与并发确定性。
type Store struct {
	mu       sync.RWMutex
	docs     map[string]*Document
	inflight map[string]*sync.Mutex // 同一 ID 的并发导入串行化
}

// NewStore 创建空存储。
func NewStore() *Store {
	return &Store{docs: map[string]*Document{}, inflight: map[string]*sync.Mutex{}}
}

// docID 由策略版本与原始内容派生稳定 ID。
func docID(policyVersion string, input []byte) string {
	h := sha256.New()
	h.Write([]byte(policyVersion))
	h.Write([]byte{0})
	h.Write(input)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Import 净化并入库一篇文档。
// 幂等：相同输入与策略版本重复导入返回已存在的记录，不重复净化、不产生重复条目。
// 并发安全：同一（内容, 策略）在并发请求下结果确定。
func (s *Store) Import(input []byte, policyVersion string, lim Limits) (*Document, error) {
	id := docID(policyVersion, input)

	// 快路径：已入库直接返回。
	s.mu.RLock()
	if d, ok := s.docs[id]; ok {
		s.mu.RUnlock()
		return d, nil
	}
	s.mu.RUnlock()

	// 同一 ID 的并发导入串行化，避免重复净化副作用。
	s.mu.Lock()
	mu, ok := s.inflight[id]
	if !ok {
		mu = &sync.Mutex{}
		s.inflight[id] = mu
	}
	s.mu.Unlock()

	mu.Lock()
	defer mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.inflight, id)
		s.mu.Unlock()
	}()

	// 拿到串行锁后再查一次，可能已被并发请求导入。
	s.mu.RLock()
	if d, ok := s.docs[id]; ok {
		s.mu.RUnlock()
		return d, nil
	}
	s.mu.RUnlock()

	res, err := Sanitize(input, policyVersion, lim)
	if err != nil {
		return nil, err
	}
	doc := &Document{
		ID:            id,
		HTML:          res.HTML,
		PolicyVersion: res.PolicyVersion,
		Issues:        res.Issues,
	}
	s.mu.Lock()
	s.docs[id] = doc
	s.mu.Unlock()
	return doc, nil
}

// Get 按 ID 查询文档。
func (s *Store) Get(id string) (*Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.docs[id]
	return d, ok
}

// Len 返回已入库文档数。
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.docs)
}
