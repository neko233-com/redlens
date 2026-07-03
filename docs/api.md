# redlens API 文档

## 基础信息

- **Base URL**: `http://localhost:8080`
- **Content-Type**: `application/json`

## 端点

### 健康检查

```
GET /api/health
```

**响应**:

```json
{
  "status": "ok"
}
```

---

### 列出扫描器

```
GET /api/scanners
```

**响应**:

```json
{
  "scanners": ["web", "network", "host"]
}
```

---

### 执行扫描

```
POST /api/scan
```

**请求体**:

```json
{
  "targets": [
    {
      "host": "192.168.1.100",
      "port": 80,
      "scheme": "http",
      "path": "/",
      "metadata": {}
    }
  ],
  "scanners": ["web", "network", "host"]
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `targets` | `Target[]` | 是 | 扫描目标列表 |
| `targets[].host` | `string` | 是 | 目标主机 IP 或域名 |
| `targets[].port` | `int` | 是 | 目标端口 |
| `targets[].scheme` | `string` | 否 | `http` 或 `https`，默认 `http` |
| `targets[].path` | `string` | 否 | 路径前缀 |
| `targets[].metadata` | `map` | 否 | 自定义元数据 |
| `scanners` | `string[]` | 否 | 要运行的扫描器，空则运行全部 |

**响应**:

```json
{
  "results": [
    {
      "vulns": [
        {
          "id": "WEB-001",
          "severity": "Medium",
          "title": "Admin Panel Exposed",
          "description": "Admin panel found at /admin",
          "evidence": [
            {
              "type": "Log",
              "content": "GET /admin returned 200",
              "proof_data": null,
              "timestamp": "2026-07-03T22:00:00Z"
            }
          ],
          "remediation": "Restrict access to admin panels via IP whitelist or VPN",
          "cvss": 5.3
        }
      ],
      "evidence": [],
      "scan_time": "2026-07-03T22:00:00Z",
      "duration": 1234567890
    }
  ],
  "summary": {
    "total": 5,
    "duration": "1.234s"
  }
}
```

**错误响应**:

| 状态码 | 说明 |
|--------|------|
| 400 | 请求格式错误或无目标 |
| 500 | 扫描执行失败 |

## 数据模型

### Target

```go
type Target struct {
    Host     string            `json:"host"`
    Port     int               `json:"port"`
    Scheme   string            `json:"scheme"`
    Path     string            `json:"path"`
    Metadata map[string]string `json:"metadata"`
}
```

### Vulnerability

```go
type Vulnerability struct {
    ID          string     `json:"id"`
    Severity    Severity   `json:"severity"`
    Title       string     `json:"title"`
    Description string     `json:"description"`
    Evidence    []Evidence `json:"evidence"`
    Remediation string     `json:"remediation"`
    CVSS        float64    `json:"cvss"`
}
```

### Severity 枚举

| 值 | 说明 | CVSS 范围 |
|----|------|-----------|
| `Critical` | 严重 | 9.0 - 10.0 |
| `High` | 高危 | 7.0 - 8.9 |
| `Medium` | 中危 | 4.0 - 6.9 |
| `Low` | 低危 | 0.1 - 3.9 |
| `Info` | 信息 | 0.0 |

### Evidence

```go
type Evidence struct {
    Type      EvidenceType   `json:"type"`
    Content   string         `json:"content"`
    ProofData map[string]any `json:"proof_data"`
    Timestamp time.Time      `json:"timestamp"`
}
```

### EvidenceType 枚举

| 值 | 说明 |
|----|------|
| `Credential` | 泄露的凭据 (账号密码) |
| `Screenshot` | 截图证据 |
| `PoC` | 攻击验证脚本 |
| `Log` | 日志/检测记录 |

## 使用示例

### cURL

```bash
# 健康检查
curl http://localhost:8080/api/health

# 列出扫描器
curl http://localhost:8080/api/scanners

# 扫描目标
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [{"host": "192.168.1.100", "port": 80, "scheme": "http"}]
  }'
```

### Go

```go
resp, _ := http.Post(
    "http://localhost:8080/api/scan",
    "application/json",
    strings.NewReader(`{
        "targets": [{"host": "192.168.1.100", "port": 80, "scheme": "http"}]
    }`),
)

var result api.ScanResponse
json.NewDecoder(resp.Body).Decode(&result)
```

### JavaScript

```javascript
const resp = await fetch('/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    targets: [{ host: '192.168.1.100', port: 80, scheme: 'http' }],
  }),
})

const data = await resp.json()
console.log(`Found ${data.summary.total} vulnerabilities`)
```
