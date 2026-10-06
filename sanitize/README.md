# document-sanitize-pipeline-go

面向富文本导入的内容净化与规范化管线。把编辑器或其他不可信来源提交的标记文本
转换成一个只包含安全内容的规范形态，再交给下游消费。整条链路只在本进程内完成，
不依赖外部服务，同一份输入与策略的结果在本地稳定复现。

## 处理链路

```
输入 → 容错解析(Parse) → 统一中间结构(Node 树) → 白名单净化(Policy.Sanitize)
     → 规范化输出(Render) → 版本化入库(Store)
```

大文档走 `SanitizeStream`：流式分词 + 事件式净化，不构建整棵树。

## 净化语义

### 1. 容错解析（parser.go）

- 容忍畸形标签、未闭合标签、非法嵌套，单处畸形不会导致整篇失败。
- 恢复动作全部记录到 `ParseResult.Issues`，每条 issue 带原始输入的字节偏移
  （`Position`），可直接定位到出问题的位置。
- 恢复规则：未闭合元素在 EOF 处隐式闭合；未匹配的结束标签被忽略；
  块级元素隐式闭合未闭合的 `<p>`；相邻 `<li>` 互相隐式闭合；
  孤立的 `<` 按文本处理；注释与 `<!...>` 声明不进入输出。
- 文本与属性值中的 HTML 实体在解析时解码，渲染时重新转义，往返一致。

### 2. 白名单过滤（policy.go）

- 只有 `Policy.Elements` 中明确允许的元素会出现在输出里。
- `Policy.DropElements`（script/style/iframe/object/embed/form 等）连同整个
  子树剥离；其余未知元素剥离标签但保留子内容（unwrap）。
- 属性放行结合所在元素判断：`Policy.Attributes` 按元素配置，`"*"` 为全局规则，
  两者取并集。同名属性落在不同元素上的处理可以不同（如 `href` 在 `<a>` 上放行、
  在 `<div>` 上剥离）。
- 事件处理器（`on*`）、未知属性一律剥离。

### 3. 地址校验（url.go）

`CheckURL` 的判定规则确定且可解释：

1. 先剥离首尾空白与所有控制字符（防 `java\tscript:` 绕过）。
2. 第一个 `:` 出现在任何 `/`、`?`、`#` 之前则前缀视为协议，必须在白名单
   （http/https/mailto/tel，不区分大小写）内。
3. 无协议视为相对地址，仅当 `Policy.AllowRelativeURLs` 为真时放行。
4. `//` 开头的协议相对地址一律拒绝（实际协议取决于页面环境，无法本地确定）。
5. 以 `:` 开头不是合法相对地址，拒绝。

### 4. 样式与标识规范化（style.go / ident.go）

- 内联样式按 `Policy.AllowedStyles` 逐一筛选；含 `expression(`、`-moz-binding`、
  `@import`、`javascript:` 等危险子串的整条声明丢弃；`url(...)` 内的地址按
  URL 规则校验。输出按属性名排序，格式统一为 `prop: value; `。
- `class` 与 `id` 按稳定规则重写：`dz-` + FNV-1a(策略版本 + 标识名) 的十六进制，
  避免与宿主页面其余部分冲突。同一输入多次净化结果完全一致。

### 5. 流式处理与上限（stream.go）

- `SanitizeStream` 内存占用只与标签嵌套深度成正比，不随输入长度线性增长
  （分词缓冲 32 KiB，单标签上限 64 KiB，超限按文本恢复）。
- 超过 `Limits.MaxBytes` 返回 `*Error{Kind: ErrKindTooLarge}`，可区分、可恢复。
- 输出先写临时文件，全部成功后才提交：目标是 `*os.File` 时在同目录 rename
  （原子替换），否则一次性拷贝。处理中断不留半写入产物。

### 6. 策略版本与幂等（store.go）

- 策略按版本注册（内置 `v1`、`v2`），导入时指定版本；历史文档按入库时的
  策略语义保持可读，新策略不会改写已入库内容。
- 同一 `(id, content, policyVersion)` 重复导入是空操作，不产生重复副作用；
  同一 id 不同内容确定性覆盖。`Store` 内部加锁，并发导入结果确定。
- 策略级拒绝：输入有实质内容但净化后为空（如通篇 script），返回
  `ErrKindPolicy`。

### 7. 批量导入失败隔离

- `Store.ImportBatch` 单篇失败不影响同批其他文档。
- 失败原因通过 `Error.Kind` 区分：`ErrKindParse`（解析问题）、
  `ErrKindPolicy`（策略拒绝）、`ErrKindTooLarge`（超过上限）。
- 结果按文档 ID 排序返回，成功与失败都可通过 `Store.Get` / `Result` 查询；
  失败文档不入库。

## 配置项

| 配置 | 位置 | 说明 |
|---|---|---|
| `Limits.MaxBytes` | `SanitizeStream` / `Store.SetLimits` | 单篇文档最大输入字节数，默认 16 MiB |
| `Policy.Elements` / `DropElements` | 策略 | 允许元素 / 连子树剥离元素 |
| `Policy.Attributes` | 策略 | 按元素的属性白名单，`"*"` 全局生效 |
| `Policy.URLAttrs` | 策略 | 需要 URL 校验的属性 |
| `Policy.AllowRelativeURLs` | 策略 | 相对地址是否放行 |
| `Policy.AllowedStyles` | 策略 | 允许的 CSS 属性 |
| `Policy.RewriteIdents` / `IdentScope` | 策略 | 是否重写 class/id 及重写作用域 |

## 测试

```sh
go test ./...        # 单元测试
go test -race ./...  # 并发竞争检测
```

覆盖：畸形结构恢复与定位、白名单绕过（事件属性、unwrap、条件注释）、
协议绕过（控制字符、大小写、data:/协议相对地址）、样式与类名重写、
幂等与并发导入、策略版本兼容、批量失败隔离与超限分类。
