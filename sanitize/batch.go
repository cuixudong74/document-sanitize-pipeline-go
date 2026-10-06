package sanitize

// BatchItem 是批量导入中的一条输入。
type BatchItem struct {
	Key   string // 调用方标识，用于回查结果
	Input []byte
}

// BatchOutcome 是批量导入结果，成功与失败均可查询。
type BatchOutcome struct {
	Succeeded map[string]*Document
	Failed    map[string]*Error
}

// ImportBatch 批量导入，单篇失败不影响同批其他文档（失败隔离）。
// 失败原因可通过 *Error.Kind 区分解析问题、策略拒绝或超过上限。
func (s *Store) ImportBatch(items []BatchItem, policyVersion string, lim Limits) *BatchOutcome {
	out := &BatchOutcome{
		Succeeded: make(map[string]*Document, len(items)),
		Failed:    map[string]*Error{},
	}
	for _, it := range items {
		doc, err := s.Import(it.Input, policyVersion, lim)
		if err != nil {
			if e, ok := err.(*Error); ok {
				out.Failed[it.Key] = e
			} else {
				out.Failed[it.Key] = &Error{Kind: ErrKindParse, Message: err.Error()}
			}
			continue
		}
		out.Succeeded[it.Key] = doc
	}
	return out
}
