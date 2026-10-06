# document-sanitize-pipeline-go

面向富文本导入的内容净化与规范化管线。把编辑器或其他不可信来源提交的标记文本
转换为只包含安全内容的规范形态，再交给下游消费。整条链路在本进程内完成，
不依赖外部服务，同一份输入在本地可稳定复现同一结果。

## 处理链路

```
输入标记文本
  → 容错解析（统一中间结构 + 问题定位）
  → 白名单过滤（元素 / 属性 / 取值）
  → URL 校验（协议与形态）
  → 样式与类名规范化（筛选 + 稳定重写）
  → 规范化输出（确定性格式）
```

## 净化语义

### 容错解析（`Parse` / `ParseReader`）

- 容忍畸形标签、未闭合标签与非法嵌套，单处畸形不会导致整篇失败。
- 恢复规则确定：块级元素隐式关闭未闭合的 `<p>`；`<li>`、`<td>/<th>`、`<tr>`
  相互隐式关闭；多余的结束标签被忽略；输入结束时自动补全未闭合标签；
  无法识别为标签的 `<...` 按纯文本处理。
- 每个恢复动作都记录为 `Issue`，携带字节偏移与行列号，可定位到出问题的位置。
- `script`/`style` 等 raw text 元素的内容不参与树构建，其中的类标签文本
  不会破坏文档结构。

### 白名单过滤

- 只有策略明确允许的元素、属性与取值能出现在输出里。
- 属性是否放行结合所在元素判断：例如 `href` 在 `<a>` 上放行、在 `<img>` 上剥离。
- 不在白名单的元素默认"去壳留子"（保留子内容）；`script`、`style`、`iframe`、
  `object`、`embed`、`applet`、`template`、`noscript` 整棵子树丢弃。
- 事件处理属性（`on*`）等未列入白名单的属性一律剥离。

### URL 校验（`CheckURL`）

判定规则确定且可解释：

1. 先做 HTML 实体解码并剔除空白与控制字符——`javascript&#58;`、`java&#9;script:`
   等浏览器会还原的写法无法绕过检查；
2. 含 scheme 的绝对地址：scheme 必须在策略白名单内（默认 `http`/`https`/`mailto`）；
3. 协议相对地址（`//host/path`）与相对地址：仅当策略 `AllowRelativeURL` 为真时保留；
4. 其余形态（空值、无法解析的畸形值）一律清除。

### 样式与类名规范化

- 内联样式按策略允许的属性逐一筛选；含 `expression()`、`javascript:`、
  `@import`、未通过 URL 校验的 `url(...)` 等危险形态的声明整条剥离。
- 类名与 id 按稳定规则重写：加策略前缀（默认 `doc-`），非法字符替换为 `-`，
  避免与宿主页面其余部分冲突。
- 样式属性输出按名称排序、同名后者覆盖前者；同一输入多次净化结果完全一致。

### 错误分类

所有可恢复错误都是 `*sanitize.Error`，通过 `Kind` 区分：

| Kind             | 含义                                     |
|------------------|------------------------------------------|
| `ErrKindParse`   | 输入无法解析（读取失败等）               |
| `ErrKindPolicy`  | 策略拒绝（未知策略版本、净化后无安全内容）|
| `ErrKindTooLarge`| 超过配置上限（字节 / 节点数 / 嵌套深度） |

处理中断时不留下半写入的产物：输出仅在完整成功后一次性返回。

## 幂等与并发保证

- `Store.Import` 的文档 ID 由（策略版本, 原始内容）的 SHA-256 派生，
  重复导入返回同一记录，不重复净化、不产生重复条目。
- 同一（内容, 策略）在并发请求下结果确定：相同 ID 的并发导入被串行化，
  先完成者的结果被后续请求复用。
- `Store.ImportBatch` 提供失败隔离：单篇失败不影响同批其他文档，
  成功与失败结果分别通过 `BatchOutcome.Succeeded` / `Failed` 查询。

## 策略版本管理

- 净化规则按版本管理（内置 `v1`、`v2`），通过 `RegisterPolicy` 注册新版本。
- 同一版本重复注册语义不同的策略会 panic，保证版本语义不可变。
- 历史文档按其导入时的策略版本入库，新策略不会改变已入库文档的内容。
- `v1`：严格结构元素 + 最小属性集，不允许 `style`/`class`/`id`。
- `v2`：在 v1 基础上放开受控的内联样式与重写后的类名、id，并新增
  `figure`/`figcaption`/`section`/`article` 元素。

## 配置项

### `Limits`（单篇处理上限，0 表示用默认值）

| 字段       | 默认值   | 说明                       |
|------------|----------|----------------------------|
| `MaxBytes` | 4 MiB    | 输入字节数上限             |
| `MaxNodes` | 100000   | 中间结构节点数上限         |
| `MaxDepth` | 256      | 元素嵌套深度上限           |

流式处理（`ParseReader` / `SanitizeReader`）在读取层限流，
超过 `MaxBytes` 立即失败，不会把超限输入全部载入内存。

### `Policy`（策略）

| 字段               | 说明                                       |
|--------------------|--------------------------------------------|
| `Elements`         | 元素白名单及每个元素的属性规则             |
| `URLSchemes`       | 允许的 URL 协议                            |
| `AllowRelativeURL` | 是否放行相对与协议相对地址                 |
| `CSSProperties`    | 允许保留的内联样式属性                     |
| `ClassPrefix`      | 类名 / id 重写前缀                         |
| `DropComments`     | 是否剥离注释                               |

## 使用示例

```go
store := sanitize.NewStore()

// 单篇导入（幂等）
doc, err := store.Import(input, sanitize.PolicyV2, sanitize.Limits{})
if err != nil {
    if e, ok := err.(*sanitize.Error); ok && e.Kind == sanitize.ErrKindTooLarge {
        // 超过上限，可提示用户拆分后重试
    }
}

// 批量导入（失败隔离）
out := store.ImportBatch(items, sanitize.PolicyV2, sanitize.Limits{})
for key, doc := range out.Succeeded { /* ... */ }
for key, e := range out.Failed {
    log.Printf("%s failed: kind=%s msg=%s", key, e.Kind, e.Message)
}
```

## 测试

```sh
go test ./... -race
```

覆盖：畸形结构恢复、白名单绕过、协议绕过、样式与类名重写、
幂等与并发导入、策略版本兼容、流式限流与批量失败隔离。
