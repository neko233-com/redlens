# redlens 架构文档

## 系统架构

```
┌─────────────────────────────────────────────────────┐
│                   React Frontend                     │
│              (Vite 8 + React 19)                     │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐         │
│  │ Dashboard │ │    Scan   │ │  Reports  │         │
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘         │
│        └──────────────┼──────────────┘               │
│                       │ HTTP                         │
└───────────────────────┼─────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────┐
│                 REST API (Go)                        │
│              ┌────────┴────────┐                     │
│              │   API Server    │                     │
│              │  :8080          │                     │
│              └────────┬────────┘                     │
│                       │                              │
│  ┌────────────────────┼────────────────────┐        │
│  │                    │                    │        │
│  ▼                    ▼                    ▼        │
│ ┌──────────┐   ┌──────────┐   ┌──────────┐        │
│ │Web Scan  │   │Net Scan  │   │Host Scan │        │
│ └──────────┘   └──────────┘   └──────────┘        │
│                       │                              │
│              ┌────────┴────────┐                     │
│              │  Report Engine  │                     │
│              │  HTML + JSON    │                     │
│              └─────────────────┘                     │
└─────────────────────────────────────────────────────┘
```

## 核心组件

### 1. Scanner Engine

**路径**: `internal/scanner/engine.go`

扫描引擎负责管理扫描器插件的注册和调度。

```go
type Engine struct {
    scanners map[string]Scanner
    mu       sync.RWMutex
}
```

**核心方法**:

| 方法 | 说明 |
|------|------|
| `Register(scanner)` | 注册扫描器插件 |
| `Run(ctx, name, target)` | 运行指定扫描器 |
| `RunAll(ctx, targets)` | 运行所有已注册扫描器 |
| `List()` | 列出所有已注册扫描器名称 |

**执行流程**:

```
1. 接收扫描请求
2. 解析目标列表
3. 遍历所有已注册扫描器
4. 对每个目标执行每个扫描器
5. 收集所有结果
6. 返回聚合结果
```

### 2. Scanner Plugin

**路径**: `internal/scanner/plugin.go`

所有扫描器必须实现 `Scanner` 接口：

```go
type Scanner interface {
    Name() string
    Description() string
    Scan(ctx context.Context, target *Target) (*Result, error)
}
```

**数据流**:

```
Target → Scanner.Scan() → Result
                              ├── Vulnerability[]
                              └── Evidence[]
```

### 3. Report Engine

**路径**: `internal/report/`

报告生成引擎支持两种输出格式：

| 格式 | 文件 | 说明 |
|------|------|------|
| JSON | `report.go` | 结构化数据，便于程序处理 |
| HTML | `html.go` | 可视化报告，便于人工查看 |

**报告结构**:

```go
type Report struct {
    Summary   Summary           // 统计概览
    Vulns     []VulnSummary     // 漏洞摘要
    Results   []*scanner.Result // 完整结果
    Generated time.Time         // 生成时间
}
```

### 4. REST API

**路径**: `internal/api/`

HTTP API 服务器，提供以下端点：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/health` | GET | 健康检查 |
| `/api/scanners` | GET | 列出扫描器 |
| `/api/scan` | POST | 执行扫描 |

**请求处理流程**:

```
1. 解析请求体
2. 验证目标列表
3. 创建带超时的 context (5分钟)
4. 调用 Engine.RunAll()
5. 聚合结果
6. 返回 JSON 响应
```

### 5. React Frontend

**路径**: `ui/`

基于 Vite 8 + React 19 + TypeScript 的前端应用。

**页面结构**:

| 页面 | 路由 | 功能 |
|------|------|------|
| Dashboard | `/` | 系统状态、扫描器列表 |
| Scan | `/scan` | 配置并执行扫描 |
| Reports | `/reports` | 查看扫描报告 |

**API 代理**: Vite 开发服务器将 `/api/*` 请求代理到 Go 后端 (`:8080`)。

## 数据流

### 扫描流程

```
用户输入目标
    │
    ▼
前端 POST /api/scan
    │
    ▼
API Server 解析请求
    │
    ▼
Engine.RunAll()
    │
    ├──▶ Web Scanner.Scan()
    │       │
    │       ▼
    │    检测 Web 漏洞
    │       │
    │       ▼
    │    返回 Result{Vulns, Evidence}
    │
    ├──▶ Network Scanner.Scan()
    │       │
    │       ▼
    │    端口扫描 + 弱口令检测
    │       │
    │       ▼
    │    返回 Result{Vulns, Evidence}
    │
    └──▶ Host Scanner.Scan()
            │
            ▼
         主机配置检查
            │
            ▼
         返回 Result{Vulns, Evidence}
    │
    ▼
聚合所有 Result
    │
    ▼
返回 JSON 响应
    │
    ▼
前端展示结果
```

### 证据链

每个漏洞可附带多种证据类型：

```
Vulnerability
    │
    ├──▶ Evidence (Credential)
    │       └── 泄露的账号密码
    │
    ├──▶ Evidence (Screenshot)
    │       └── 登录成功截图
    │
    ├──▶ Evidence (PoC)
    │       └── 攻击验证命令
    │
    └──▶ Evidence (Log)
            └── HTTP 请求/响应日志
```

## 部署架构

### 开发环境

```
localhost:3000 (Vite) ──proxy──▶ localhost:8080 (Go API)
```

### Docker 环境

```
┌─────────────────────────────────────┐
│         Docker Network              │
│  ┌──────────────┐ ┌──────────────┐ │
│  │ vulnerable-  │ │   redlens    │ │
│  │ web:8080     │ │   :8080      │ │
│  └──────────────┘ └──────────────┘ │
└─────────────────────────────────────┘
```

### 生产环境

```
┌─────────────────────────────────────┐
│           Load Balancer             │
└──────────────┬──────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
    ▼                     ▼
┌────────┐           ┌────────┐
│ redlens│           │ redlens│
│ :8080  │           │ :8080  │
└────────┘           └────────┘
```

## 安全考虑

### 扫描器安全

- 所有网络连接使用超时 (2-5 秒)
- context 支持取消
- 扫描结果不持久化敏感信息

### API 安全

- 请求体大小限制
- 5 分钟扫描超时
- 错误信息不泄露内部细节

### 报告安全

- 报告默认存储在本地
- 凭据信息可选脱敏
- 生产环境建议加密存储
