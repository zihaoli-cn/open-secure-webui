# OpenWebUI 三员管理系统

## 项目概述

三员管理系统是为OpenWebUI开发的独立管理平台，实现了系统管理员、授权管理员、审计管理员的三权分立管理模式，适用于保密内网环境。

### 核心特性

- **三员分权管理**：系统管理员、授权管理员、审计管理员各司其职
- **独立前后端**：基于Vue.js 3和FastAPI的现代化架构
- **数据库共享**：与OpenWebUI共享数据库，无缝集成
- **安全审计**：完整的操作审计日志和安全策略管理
- **权限隔离**：严格的角色权限控制，确保安全合规

## 技术架构

### 后端技术栈

- **框架**: FastAPI 0.115.0
- **数据库**: SQLAlchemy 2.0.23 (支持SQLite/PostgreSQL)
- **认证**: JWT + bcrypt
- **服务器**: Uvicorn 0.24.0

### 前端技术栈

- **框架**: Vue.js 3.3.4 + Composition API
- **UI库**: Element Plus 2.3.12
- **状态管理**: Pinia 2.1.6
- **路由**: Vue Router 4.2.4
- **图表**: ECharts 5.4.3
- **构建工具**: Vite 4.4.5

## 目录结构

```
open-secure-webui/
├── backend/
│   ├── administration/          # 三员管理后端
│   │   ├── config.py           # 配置文件
│   │   ├── main.py             # FastAPI应用入口
│   │   ├── models/             # 数据模型
│   │   │   └── admin_users.py  # 管理员用户模型
│   │   ├── routers/            # API路由
│   │   │   ├── auth.py         # 认证路由
│   │   │   ├── sys_admin.py    # 系统管理员路由
│   │   │   ├── auth_admin.py   # 授权管理员路由
│   │   │   └── audit_admin.py  # 审计管理员路由
│   │   ├── utils/              # 工具函数
│   │   │   ├── auth.py         # 认证工具
│   │   │   ├── database.py     # 数据库工具
│   │   │   └── openwebui_client.py  # OpenWebUI客户端
│   │   ├── middleware/         # 中间件
│   │   │   └── audit.py        # 审计中间件
│   │   ├── requirements.txt    # Python依赖
│   │   └── .env                # 环境变量
│   └── open_webui/
│       └── models/
│           ├── security.py     # 安全模型（已扩展）
│           └── audit_log.py    # 审计日志模型（已扩展）
└── frontend/
    └── administration/          # 三员管理前端
        ├── src/
        │   ├── api/            # API接口
        │   ├── components/     # 通用组件
        │   ├── router/         # 路由配置
        │   ├── store/          # 状态管理
        │   ├── views/          # 页面组件
        │   │   ├── Login.vue   # 登录页面
        │   │   ├── Layout.vue  # 主布局
        │   │   ├── Dashboard.vue  # 概览页面
        │   │   ├── sys_admin/  # 系统管理员页面
        │   │   ├── auth_admin/ # 授权管理员页面
        │   │   └── audit_admin/  # 审计管理员页面
        │   ├── App.vue
        │   └── main.js
        ├── package.json
        ├── vite.config.js
        └── .env
```

## 快速开始

### 环境要求

- Python 3.11+
- Node.js 18+
- SQLite 3 或 PostgreSQL 12+

### 后端部署

1. **安装依赖**

```bash
cd backend/administration
pip install -r requirements.txt
```

2. **配置环境变量**

编辑 `.env` 文件：

```bash
# 数据库配置（SQLite）
ADMIN_DB_URL=sqlite:///./admin_management.db

# 或使用PostgreSQL
# ADMIN_DB_URL=postgresql://user:password@localhost:5432/openwebui

# JWT配置
ADMIN_JWT_SECRET=your-secret-key-change-in-production
ADMIN_JWT_ALGORITHM=HS256

# Open WebUI集成
OPENWEBUI_URL=http://localhost:3000
OPENWEBUI_API_KEY=

# 服务配置
ADMIN_HOST=0.0.0.0
ADMIN_PORT=3001
DEBUG=False
```

3. **启动后端服务**

```bash
python main.py
```

后端服务将在 `http://localhost:3001` 启动。

API文档访问：
- Swagger UI: http://localhost:3001/docs
- ReDoc: http://localhost:3001/redoc

### 前端部署

1. **安装依赖**

```bash
cd frontend/administration
npm install
```

2. **配置环境变量**

编辑 `.env` 文件：

```bash
VITE_API_BASE_URL=http://localhost:3001/api
VITE_APP_TITLE=三员管理系统
```

3. **启动开发服务器**

```bash
npm run dev
```

前端服务将在 `http://localhost:3002` 启动。

4. **构建生产版本**

```bash
npm run build
```

构建产物将输出到 `dist/` 目录。

## 内置账户

系统启动时会自动创建三个内置管理员账户：

| 角色 | 用户名 | 初始密码 | 权限 |
|------|--------|----------|------|
| 系统管理员 | sys_admin | SysAdmin123! | 用户管理、模型管理、API Key管理 |
| 授权管理员 | auth_admin | AuthAdmin123! | 安全配置、IP白名单、密码策略 |
| 审计管理员 | audit_admin | AuditAdmin123! | 审计日志、统计分析、操作监控 |

**⚠️ 重要提示**：首次登录后请立即修改默认密码！

## 功能说明

### 系统管理员功能

1. **API Key管理**
   - 生成OpenWebUI的API Key
   - 查看、删除API Key
   - 验证API Key有效性

2. **用户管理**（通过OpenWebUI API代理）
   - 查看用户列表
   - 管理用户角色
   - 用户状态管理

3. **模型管理**（通过OpenWebUI API代理）
   - 添加/删除模型
   - 模型配置管理

4. **组管理**（通过OpenWebUI API代理）
   - 创建/编辑用户组
   - 组成员管理

### 授权管理员功能

1. **安全配置**
   - 登录失败次数限制
   - 账户锁定时长
   - 密码过期策略
   - IP白名单开关

2. **IP白名单管理**
   - 添加/删除IP地址
   - IP地址验证
   - 批量操作

3. **密码策略**
   - 密码复杂度要求
   - 密码过期时间
   - 强制密码更换

### 审计管理员功能

1. **审计日志查看**
   - 查看所有管理员操作记录
   - 高级搜索和筛选
   - 日志详情查看
   - 数据导出

2. **统计分析**
   - 操作类型分布（饼图）
   - 时间趋势分析（折线图）
   - 用户活跃度分析（柱状图）
   - 异常操作分析

3. **实时监控**
   - 最近操作记录
   - 系统健康状态
   - 异常操作告警

## 数据库表结构

### 三员管理系统表

1. **admin_users** - 管理员用户表
   - 存储三员管理员账户信息
   - 独立于OpenWebUI的用户表

2. **admin_api_keys** - API Key管理表
   - 存储生成的API Key
   - 用于访问OpenWebUI管理API

3. **admin_config** - 管理配置表
   - 存储系统配置信息
   - JSON格式的灵活配置

4. **audit_logs** - 审计日志表
   - 记录所有管理员操作
   - 自动记录，不可修改

### OpenWebUI扩展表

1. **user_ip_whitelist** - IP白名单表
2. **login_attempts** - 登录尝试记录表
3. **user_lock_status** - 用户锁定状态表
4. **password_policy** - 密码策略表
5. **security_config** - 安全配置表
6. **audit_config** - 审计配置表

## 安全特性

### 认证安全

- JWT Token认证，24小时过期
- bcrypt密码加密
- 强制密码复杂度（至少8位）
- 密码过期策略（90天）

### 权限安全

- 严格的角色权限验证
- 路由守卫
- API权限控制
- 数据访问控制

### 审计安全

- 所有操作自动记录审计日志
- 审计日志不可修改
- 审计管理员可查看所有操作
- 数据变更追踪

## 开发指南

### 后端开发

1. **添加新的API端点**

在对应的路由文件中添加：

```python
@router.get("/new-endpoint")
async def new_endpoint(
    current_user: dict = Depends(AuthManager.get_current_sys_admin),
    db: Session = Depends(get_db)
):
    # 实现逻辑
    return {"result": "success"}
```

2. **添加审计日志**

```python
from middleware import AdminAuditLogger

AdminAuditLogger.log_admin_action(
    user_id=current_user["id"],
    username=current_user["username"],
    user_role=current_user["admin_role"],
    action="ACTION_NAME",
    resource_type="resource_type",
    resource_id="resource_id",
    details="操作详情"
)
```

### 前端开发

1. **添加新页面**

在 `src/views/` 目录下创建Vue组件：

```vue
<template>
  <div class="page-container">
    <!-- 页面内容 -->
  </div>
</template>

<script setup>
// 页面逻辑
</script>

<style scoped>
/* 页面样式 */
</style>
```

2. **添加路由**

在 `src/router/routes.js` 中添加：

```javascript
{
  path: 'new-page',
  name: 'NewPage',
  component: () => import('@/views/NewPage.vue'),
  meta: { title: '新页面', role: 'sys_admin' }
}
```

## 生产部署

### 使用Docker部署

1. **后端Dockerfile**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY backend/administration/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/administration .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3001"]
```

2. **前端Dockerfile**

```dockerfile
FROM node:18-alpine as builder

WORKDIR /app

COPY frontend/administration/package*.json ./
RUN npm install

COPY frontend/administration .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
```

3. **docker-compose.yml**

```yaml
version: '3.8'

services:
  admin-backend:
    build:
      context: .
      dockerfile: backend/administration/Dockerfile
    ports:
      - "3001:3001"
    environment:
      - ADMIN_DB_URL=postgresql://user:password@db:5432/openwebui
      - ADMIN_JWT_SECRET=your-secret-key
      - OPENWEBUI_URL=http://openwebui:3000
    depends_on:
      - db

  admin-frontend:
    build:
      context: .
      dockerfile: frontend/administration/Dockerfile
    ports:
      - "3002:80"
    depends_on:
      - admin-backend

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=openwebui
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

### Nginx反向代理配置

```nginx
server {
    listen 80;
    server_name admin.example.com;

    # 前端
    location / {
        proxy_pass http://localhost:3002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # 后端API
    location /api {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 故障排查

### 后端启动失败

1. **检查Python版本**
```bash
python --version  # 应该是3.11+
```

2. **检查依赖安装**
```bash
pip list | grep fastapi
```

3. **检查数据库连接**
```bash
# 查看日志
tail -f logs/app.log
```

### 前端启动失败

1. **检查Node.js版本**
```bash
node --version  # 应该是18+
```

2. **清除缓存重新安装**
```bash
rm -rf node_modules package-lock.json
npm install
```

3. **检查端口占用**
```bash
lsof -i :3002
```

### 登录失败

1. **检查后端服务是否运行**
```bash
curl http://localhost:3001/health
```

2. **检查数据库表是否创建**
```bash
# SQLite
sqlite3 admin_management.db ".tables"

# PostgreSQL
psql -U user -d openwebui -c "\dt"
```

3. **重置管理员密码**
```python
# 进入Python shell
python
>>> from models.admin_users import AdminUser
>>> from utils.database import get_db
>>> with next(get_db()) as db:
...     AdminUser.change_password(db, "sys_admin", "旧密码", "新密码")
```

## 常见问题

### Q: 如何修改管理员密码？

A: 登录后点击右上角用户名，选择"修改密码"。

### Q: 忘记管理员密码怎么办？

A: 需要直接操作数据库重置密码，或删除数据库重新初始化。

### Q: 如何与OpenWebUI集成？

A: 确保`OPENWEBUI_URL`配置正确，并在OpenWebUI中生成API Key填入`OPENWEBUI_API_KEY`。

### Q: 审计日志保留多久？

A: 默认永久保留，可以通过API手动清理超过指定天数的日志。

### Q: 支持LDAP认证吗？

A: 当前版本不支持，可以根据需要扩展认证模块。

## 更新日志

### v1.0.0 (2024-11-24)

- ✅ 完整的三员管理功能
- ✅ 前后端分离架构
- ✅ JWT认证和权限控制
- ✅ 审计日志自动记录
- ✅ 安全配置管理
- ✅ IP白名单管理
- ✅ API Key管理
- ✅ OpenWebUI集成

## 贡献指南

欢迎提交Issue和Pull Request！

## 许可证

本项目采用与OpenWebUI相同的许可证。

## 联系方式

如有问题或建议，请通过GitHub Issue联系。
