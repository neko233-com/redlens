# redlens

Red Team Vulnerability Scanner & Reporting Tool

全栈安全评估工具，用于对自家基础设施进行漏洞扫描，生成包含完整证据链的合规报告。

## 功能特性

- **Web 漏洞扫描** — SQL 注入、XSS、Admin 面板暴露、目录列表、安全头缺失检测
- **网络安全审计** — 端口扫描、服务指纹识别、弱口令检测 (Redis/MySQL/PostgreSQL)
- **主机配置检查** — DNS 解析、Telnet/FTP 暴露、权限分析
- **完整证据链** — 报告包含凭据、截图、PoC 脚本、时间戳、影响范围
- **合规报告** — HTML + JSON 双格式，映射 OWASP Top 10 / CIS 基线
- **Docker 模拟** — 内置故意有漏洞的测试应用，用于验证扫描能力
- **跨平台** — Windows / Linux / macOS

## 快速开始

### 构建

```bash
git clone https://github.com/neko233-com/redlens.git
cd redlens
go build -o redlens ./cmd/redlens
```

### 启动服务

```bash
# 启动 API 服务 (端口 8080)
./redlens serve

# 启动前端开发服务器 (端口 3000)
cd ui && npm install && npm run dev
```

打开浏览器访问 `http://localhost:3000`

### Docker 模拟测试

```bash
cd docker
docker-compose up --build
```

这将启动：
- `vulnerable-web` — 故意有漏洞的 Flask 应用 (端口 8080)
- `redlens` — 扫描器服务

## 项目结构

```
redlens/
├── cmd/redlens/              # Go CLI 入口
│   └── main.go
├── internal/
│   ├── scanner/
│   │   ├── plugin.go         # 扫描器接口定义
│   │   ├── engine.go         # 扫描引擎 (注册/调度)
│   │   └── plugins/
│   │       ├── web/          # Web 漏洞扫描器
│   │       ├── network/      # 网络扫描器
│   │       └── host/         # 主机配置扫描器
│   ├── report/
│   │   ├── report.go         # 报告生成 (JSON)
│   │   └── html.go           # HTML 报告渲染
│   └── api/
│       ├── server.go         # HTTP 服务器
│       └── handlers.go       # API 路由处理
├── ui/                       # Vite 8 + React 19 前端
│   ├── src/
│   │   ├── App.tsx           # 路由配置
│   │   └── pages/
│   │       ├── Dashboard.tsx # 仪表盘
│   │       ├── Scan.tsx      # 扫描配置
│   │       └── Reports.tsx   # 报告查看
│   └── vite.config.ts
├── docker/
│   ├── docker-compose.yml    # Docker 编排
│   └── vulnerable-app/       # 漏洞测试应用
├── docs/                     # GitHub Pages 文档
├── .github/workflows/        # CI/CD
├── Dockerfile                # 生产镜像
├── Makefile                  # 构建脚本
└── go.mod
```

## API 文档

详见 [docs/api.md](docs/api.md)

### 核心端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/scanners` | 列出可用扫描器 |
| POST | `/api/scan` | 执行扫描 |

### 扫描请求示例

```json
{
  "targets": [
    {
      "host": "192.168.1.100",
      "port": 80,
      "scheme": "http"
    }
  ],
  "scanners": ["web", "network", "host"]
}
```

## 扫描器插件

详见 [docs/scanners.md](docs/scanners.md)

| 插件 | 说明 | 检测项 |
|------|------|--------|
| `web` | Web 漏洞扫描 | Admin 面板、目录列表、安全头 |
| `network` | 网络安全审计 | 端口扫描、服务指纹、弱口令 |
| `host` | 主机配置检查 | DNS、Telnet/FTP、权限 |

### 编写自定义扫描器

```go
package myscanner

import (
    "context"
    "github.com/redlens/redlens/internal/scanner"
)

type MyScanner struct{}

func (m *MyScanner) Name() string { return "my-scanner" }
func (m *MyScanner) Description() string { return "Custom scanner" }

func (m *MyScanner) Scan(ctx context.Context, target *scanner.Target) (*scanner.Result, error) {
    result := &scanner.Result{ScanTime: time.Now()}
    // 你的扫描逻辑
    return result, nil
}
```

在 `cmd/redlens/main.go` 中注册：

```go
engine.Register(myscanner.New())
```

## 报告格式

### JSON 报告

```json
{
  "summary": {
    "total": 12,
    "by_severity": {
      "Critical": 2,
      "High": 3,
      "Medium": 4,
      "Low": 2,
      "Info": 1
    }
  },
  "vulns": [
    {
      "id": "NET-002-REDIS",
      "severity": "Critical",
      "title": "Redis No Authentication",
      "cvss": 9.8
    }
  ],
  "generated": "2026-07-03T22:00:00Z"
}
```

### HTML 报告

生成带暗色主题的交互式 HTML 报告，包含：
- 漏洞统计概览 (按严重度分色)
- 漏洞详情表格 (ID、严重度、标题、CVSS)
- 证据展示 (凭据、日志、PoC)
- 修复建议

## Docker

### 生产部署

```bash
docker build -t redlens .
docker run -p 8080:8080 redlens
```

### 模拟测试环境

```bash
cd docker
docker-compose up --build
```

访问 `http://localhost:8080` 查看漏洞测试应用。

## 技术栈

- **后端**: Go 1.22+, net/http
- **前端**: Vite 8, React 19, TypeScript
- **容器**: Docker, Docker Compose
- **CI/CD**: GitHub Actions, GitHub Pages

## License

MIT
