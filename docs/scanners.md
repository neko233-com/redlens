# redlens 扫描器插件文档

## 概述

redlens 采用插件式架构，每个扫描器实现 `Scanner` 接口。扫描器可以独立运行，也可以通过引擎组合执行。

## 接口定义

```go
type Scanner interface {
    Name() string
    Description() string
    Scan(ctx context.Context, target *Target) (*Result, error)
}
```

## 内置扫描器

### 1. Web 扫描器 (`web`)

**路径**: `internal/scanner/plugins/web/`

**检测项**:

| ID | 严重度 | 检测项 | 说明 |
|----|--------|--------|------|
| WEB-001 | Medium | Admin 面板暴露 | 检测 /admin, /wp-admin, /phpmyadmin 等路径 |
| WEB-002 | Low | 目录列表 | 检测 Web 服务器是否开启目录列表 |
| WEB-003-* | Low | 安全头缺失 | X-Frame-Options, X-Content-Type-Options, HSTS |

**检测逻辑**:

1. 遍历常见 Admin 路径，检查是否返回 200/302
2. 请求根路径，检查响应是否包含 `Index of /`
3. 检查 HTTP 响应头中的安全配置

**使用示例**:

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [{"host": "192.168.1.100", "port": 80, "scheme": "http"}],
    "scanners": ["web"]
  }'
```

---

### 2. 网络扫描器 (`network`)

**路径**: `internal/scanner/plugins/network/`

**检测项**:

| ID | 严重度 | 检测项 | 说明 |
|----|--------|--------|------|
| NET-001-* | Info | 开放端口 | 扫描 18 个常见端口 |
| NET-002-REDIS | Critical | Redis 无认证 | Redis 服务可未授权访问 |
| NET-002-* | Critical | 数据库弱口令 | MySQL/PostgreSQL 默认凭据 |

**扫描端口列表**:

```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP),
53 (DNS), 80 (HTTP), 110 (POP3), 143 (IMAP),
443 (HTTPS), 993 (IMAPS), 995 (POP3S),
3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL),
6379 (Redis), 8080 (HTTP-Alt), 8443 (HTTPS-Alt),
27017 (MongoDB)
```

**弱口令检测**:

- Redis: 检测是否可未授权连接
- MySQL/PostgreSQL: 检测默认凭据 (admin:admin, root:root, root:(empty))

**使用示例**:

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [{"host": "192.168.1.100", "port": 22}],
    "scanners": ["network"]
  }'
```

---

### 3. 主机扫描器 (`host`)

**路径**: `internal/scanner/plugins/host/`

**检测项**:

| ID | 严重度 | 检测项 | 说明 |
|----|--------|--------|------|
| HOST-001 | Low | DNS 解析问题 | 主机名无法解析 |
| HOST-002 | High | Telnet 服务 | 端口 23 开放 (明文传输) |
| HOST-003 | Medium | FTP 服务 | 端口 21 开放 (明文传输) |
| HOST-004 | High | Root 权限运行 | 扫描器以 root 权限运行 (仅 Linux) |

**检测逻辑**:

1. 尝试 DNS 解析目标主机名
2. 检查 Telnet (23) 和 FTP (21) 端口
3. 在本地扫描时检查进程权限

**使用示例**:

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [{"host": "192.168.1.100", "port": 80}],
    "scanners": ["host"]
  }'
```

## 编写自定义扫描器

### 步骤 1: 创建扫描器包

```
internal/scanner/plugins/myplugin/
├── myplugin.go
└── myplugin_test.go
```

### 步骤 2: 实现 Scanner 接口

```go
package myplugin

import (
    "context"
    "time"
    "github.com/redlens/redlens/internal/scanner"
)

type MyScanner struct{}

func New() *MyScanner {
    return &MyScanner{}
}

func (m *MyScanner) Name() string {
    return "my-scanner"
}

func (m *MyScanner) Description() string {
    return "My custom vulnerability scanner"
}

func (m *MyScanner) Scan(ctx context.Context, target *scanner.Target) (*scanner.Result, error) {
    result := &scanner.Result{
        ScanTime: time.Now(),
    }

    // 你的扫描逻辑
    vuln := m.checkVulnerability(ctx, target)
    if vuln != nil {
        result.Vulns = append(result.Vulns, *vuln)
    }

    return result, nil
}

func (m *MyScanner) checkVulnerability(ctx context.Context, target *scanner.Target) *scanner.Vulnerability {
    // 检测逻辑
    return &scanner.Vulnerability{
        ID:          "CUSTOM-001",
        Severity:    scanner.SeverityHigh,
        Title:       "Custom Vulnerability",
        Description: "Description of the vulnerability",
        Evidence: []scanner.Evidence{
            {
                Type:    scanner.EvidenceLog,
                Content: "Evidence details",
            },
        },
        Remediation: "How to fix this issue",
        CVSS:        7.5,
    }
}
```

### 步骤 3: 编写测试

```go
package myplugin

import (
    "context"
    "testing"
    "github.com/redlens/redlens/internal/scanner"
)

func TestMyScannerName(t *testing.T) {
    s := New()
    if s.Name() != "my-scanner" {
        t.Errorf("expected name 'my-scanner', got %q", s.Name())
    }
}

func TestMyScannerScan(t *testing.T) {
    s := New()
    target := &scanner.Target{
        Host: "127.0.0.1",
        Port: 8080,
    }

    result, err := s.Scan(context.Background(), target)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    if result == nil {
        t.Fatal("expected non-nil result")
    }
}
```

### 步骤 4: 注册扫描器

编辑 `cmd/redlens/main.go`:

```go
import (
    "github.com/redlens/redlens/internal/scanner/plugins/myplugin"
)

func main() {
    engine := scanner.NewEngine()
    engine.Register(web.New())
    engine.Register(network.New())
    engine.Register(host.New())
    engine.Register(myplugin.New())  // 添加你的扫描器
    // ...
}
```

### 步骤 5: 运行测试

```bash
go test ./internal/scanner/plugins/myplugin/ -v
```

## 证据类型

| 类型 | 说明 | 示例 |
|------|------|------|
| `Credential` | 泄露的凭据 | {"username": "admin", "password": "admin"} |
| `Screenshot` | 截图证据 | Base64 编码的截图 |
| `PoC` | 攻击验证脚本 | curl 命令、Python 脚本 |
| `Log` | 日志/检测记录 | HTTP 请求/响应日志 |

## 严重度与 CVSS

| 严重度 | CVSS 范围 | 说明 |
|--------|-----------|------|
| Critical | 9.0 - 10.0 | 需立即修复，可直接导致系统沦陷 |
| High | 7.0 - 8.9 | 需尽快修复，可能导致数据泄露 |
| Medium | 4.0 - 6.9 | 需计划修复，存在安全隐患 |
| Low | 0.1 - 3.9 | 建议修复，改善安全配置 |
| Info | 0.0 | 信息收集，无直接风险 |
