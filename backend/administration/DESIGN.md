# 三员管理系统设计文档

## 项目概述

### 目标
开发一个独立的Web服务，为Open WebUI提供三员管理功能，包括系统管理员、安全管理员、审计管理员三个角色的管理界面。

### 技术栈
- **后端**: FastAPI + SQLAlchemy + JWT
- **前端**: Vue.js 3 + Element Plus + Vite
- **数据库**: 共享Open WebUI数据库
- **部署**: 独立服务，端口3001

## 系统架构

### 后端架构
```
backend/administration/
├── main.py                    # FastAPI应用入口
├── config.py                  # 配置文件
├── models/                    # 数据模型
│   ├── __init__.py
│   ├── admin_users.py         # 三员用户模型
│   ├── admin_config.py        # 管理配置模型
│   └── admin_audit.py         # 管理审计模型
├── routers/                   # API路由
│   ├── __init__.py
│   ├── auth.py               # 认证路由
│   ├── sys_admin.py          # 系统管理员路由
│   ├── auth_admin.py         # 安全管理员路由
│   └── audit_admin.py        # 审计管理员路由
├── utils/                     # 工具函数
│   ├── __init__.py
│   ├── auth.py               # 认证工具
│   ├── security.py           # 安全工具
│   ├── database.py           # 数据库工具
│   └── openwebui_client.py   # Open WebUI客户端
└── middleware/               # 中间件
    ├── __init__.py
    ├── auth.py               # 认证中间件
    └── audit.py              # 审计中间件
```

### 前端架构
```
frontend/administration/
├── src/
│   ├── main.js               # Vue应用入口
│   ├── App.vue               # 根组件
│   ├── router/               # 路由配置
│   │   ├── index.js
│   │   └── routes.js
│   ├── store/                # 状态管理
│   │   ├── index.js
│   │   └── modules/
│   │       ├── auth.js       # 认证状态
│   │       ├── sys_admin.js  # 系统管理员状态
│   │       ├── auth_admin.js # 安全管理员状态
│   │       └── audit_admin.js # 审计管理员状态
│   ├── views/                # 页面组件
│   │   ├── Login.vue         # 登录页面
│   │   ├── Layout.vue        # 主布局
│   │   ├── SysAdmin/         # 系统管理员页面
│   │   │   ├── ApiKeys.vue   # API Key管理
│   │   │   ├── UserManagement.vue # 用户管理
│   │   │   ├── ModelManagement.vue # 模型管理
│   │   │   └── GroupManagement.vue # 组管理
│   │   ├── AuthAdmin/        # 安全管理员页面
│   │   │   ├── SecurityConfig.vue # 安全配置
│   │   │   ├── IpWhitelist.vue   # IP白名单
│   │   │   └── PasswordPolicy.vue # 密码策略
│   │   └── AuditAdmin/       # 审计管理员页面
│   │       ├── AuditLogs.vue     # 审计日志
│   │       ├── Statistics.vue    # 统计分析
│   │       └── AdminActions.vue  # 管理员操作
│   ├── components/           # 通用组件
│   │   ├── common/
│   │   └── layout/
│   ├── api/                  # API接口
│   │   ├── index.js
│   │   ├── auth.js
│   │   ├── sys_admin.js
│   │   ├── auth_admin.js
│   │   └── audit_admin.js
│   └── utils/                # 工具函数
│       ├── auth.js
│       ├── request.js
│       └── permission.js
├── package.json
└── vite.config.js
```

## 数据库设计

### 扩展现有表结构

#### 1. 三员用户表 (扩展现有User表)
```sql
-- 在现有User表中添加三员管理相关字段
ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_role VARCHAR(20); -- sys_admin, auth_admin, audit_admin
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_builtin_admin BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_permissions JSONB;
```

#### 2. 管理配置表
```sql
CREATE TABLE IF NOT EXISTS admin_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 3. API Key管理表
```sql
CREATE TABLE IF NOT EXISTS admin_api_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    api_key VARCHAR(100) UNIQUE NOT NULL,
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    permissions JSONB
);
```

## API设计

### 认证API

#### POST /api/auth/login
**请求**:
```json
{
  "username": "sys_admin",
  "password": "password"
}
```

**响应**:
```json
{
  "access_token": "jwt_token",
  "token_type": "bearer",
  "user": {
    "username": "sys_admin",
    "role": "sys_admin",
    "display_name": "系统管理员"
  }
}
```

#### GET /api/auth/check-password-expiry
**响应**:
```json
{
  "is_expired": false,
  "days_remaining": 30,
  "last_change": "2024-01-01T00:00:00Z"
}
```

#### POST /api/auth/change-password
**请求**:
```json
{
  "current_password": "old_password",
  "new_password": "new_password"
}
```

### 系统管理员API

#### GET /api/sys-admin/api-keys
**响应**:
```json
{
  "api_keys": [
    {
      "id": 1,
      "name": "生产环境",
      "api_key": "sk_****",
      "created_at": "2024-01-01T00:00:00Z",
      "expires_at": "2024-12-31T23:59:59Z",
      "is_active": true
    }
  ]
}
```

#### POST /api/sys-admin/api-keys
**请求**:
```json
{
  "name": "测试环境",
  "expires_in_days": 30
}
```

#### DELETE /api/sys-admin/api-keys/{id}

#### GET /api/sys-admin/validate-api-key/{api_key}

#### GET /api/sys-admin/open-webui/users
**代理到Open WebUI的 /api/v1/auths/admin/details**

#### POST /api/sys-admin/open-webui/models
**代理到Open WebUI的模型管理API**

### 安全管理员API

#### GET /api/auth-admin/security-config
**响应**:
```json
{
  "max_failed_attempts": 5,
  "lockout_duration": 1800,
  "password_expiry_days": 90,
  "ip_whitelist_enabled": true
}
```

#### PUT /api/auth-admin/security-config
**请求**:
```json
{
  "max_failed_attempts": 10,
  "lockout_duration": 3600,
  "password_expiry_days": 60
}
```

#### GET /api/auth-admin/ip-whitelist
#### POST /api/auth-admin/ip-whitelist
#### DELETE /api/auth-admin/ip-whitelist/{id}

### 审计管理员API

#### GET /api/audit-admin/logs
**查询参数**:
- page: 页码
- size: 每页大小
- start_date: 开始时间
- end_date: 结束时间
- user_role: 用户角色
- action_type: 操作类型

**响应**:
```json
{
  "logs": [
    {
      "id": 1,
      "timestamp": "2024-01-01T10:00:00Z",
      "user_name": "sys_admin",
      "user_role": "sys_admin",
      "action": "CREATE_API_KEY",
      "resource": "api_keys",
      "details": "创建API Key: 测试环境",
      "ip_address": "192.168.1.100"
    }
  ],
  "total": 100,
  "page": 1,
  "size": 20
}
```

#### GET /api/audit-admin/stats
**响应**:
```json
{
  "total_actions": 1000,
  "actions_by_role": {
    "sys_admin": 400,
    "auth_admin": 300,
    "audit_admin": 300
  },
  "actions_by_type": {
    "LOGIN": 200,
    "CREATE": 300,
    "UPDATE": 400,
    "DELETE": 100
  },
  "recent_activity": [
    {
      "date": "2024-01-01",
      "count": 50
    }
  ]
}
```

## 权限设计

### 角色权限矩阵

| 功能模块 | sys_admin | auth_admin | audit_admin |
|---------|-----------|------------|-------------|
| 登录认证 | ✓ | ✓ | ✓ |
| 修改密码 | ✓ | ✓ | ✓ |
| API Key管理 | ✓ | ✗ | ✗ |
| Open WebUI代理 | ✓ | ✗ | ✗ |
| 安全配置管理 | ✗ | ✓ | ✗ |
| IP白名单管理 | ✗ | ✓ | ✗ |
| 密码策略管理 | ✗ | ✓ | ✗ |
| 审计日志查看 | ✗ | ✗ | ✓ |
| 统计分析查看 | ✗ | ✗ | ✓ |
| 所有操作可见 | ✗ | ✗ | ✓ |

### 权限验证逻辑

1. **JWT Token验证**: 所有API请求都需要有效的JWT Token
2. **角色权限验证**: 基于用户角色验证API访问权限
3. **审计可见性**: audit_admin可以查看所有管理员的操作记录
4. **内置账户保护**: 三个内置管理员账户不允许删除

## 安全设计

### 认证安全
- JWT Token过期时间：24小时
- 密码加密：bcrypt
- 强制密码复杂度：至少8位，包含大小写字母和数字
- 密码过期策略：90天

### 会话安全
- HTTP Only Cookie
- Secure Flag (HTTPS only)
- SameSite Strict
- CSRF保护

### 审计安全
- 所有管理操作记录审计日志
- 审计日志不可修改
- 审计管理员可以查看所有操作

## 部署配置

### 环境变量
```bash
# 数据库配置
ADMIN_DB_URL=postgresql://user:pass@localhost:5432/openwebui

# JWT配置
ADMIN_JWT_SECRET=your-secret-key
ADMIN_JWT_ALGORITHM=HS256

# 服务配置
ADMIN_HOST=0.0.0.0
ADMIN_PORT=3001

# Open WebUI集成
OPENWEBUI_URL=http://localhost:3000
OPENWEBUI_API_KEY=your-api-key
```

### Docker部署
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3001"]
```

## 开发计划

### 阶段1：后端核心 (2-3天)
- [ ] 项目结构和配置
- [ ] 数据库模型
- [ ] 认证系统
- [ ] 基础API框架

### 阶段2：后端功能 (3-4天)
- [ ] 系统管理员API
- [ ] 安全管理员API
- [ ] 审计管理员API
- [ ] Open WebUI集成

### 阶段3：前端框架 (2-3天)
- [ ] Vue项目初始化
- [ ] 路由和状态管理
- [ ] 认证界面
- [ ] 基础布局

### 阶段4：前端功能 (4-5天)
- [ ] 系统管理员界面
- [ ] 安全管理员界面
- [ ] 审计管理员界面
- [ ] 数据可视化

### 阶段5：测试优化 (2-3天)
- [ ] 功能测试
- [ ] 集成测试
- [ ] 性能优化
- [ ] 文档完善

## 风险控制

### 技术风险
- **数据库兼容性**: 确保与现有Open WebUI数据库兼容
- **API集成**: Open WebUI API变化可能导致集成问题
- **权限控制**: 复杂的权限逻辑需要充分测试

### 应对措施
- 充分的单元测试和集成测试
- API版本控制和兼容性处理
- 详细的错误日志和监控
- 逐步部署和回滚机制

## 成功标准

1. **功能完整性**: 所有三员管理功能正常运作
2. **安全性**: 权限分离彻底，无安全漏洞
3. **性能**: 响应时间在可接受范围内
4. **用户体验**: 界面简洁美观，操作流畅
5. **集成性**: 与Open WebUI无缝集成
6. **可维护性**: 代码结构清晰，易于扩展