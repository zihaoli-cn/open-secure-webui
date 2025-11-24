# 三员管理系统 - 部署和使用指南

## 系统概述

三员管理系统是一个独立的Web服务，为OpenWebUI提供系统管理员、安全管理员和审计管理员的三员管理功能。系统采用前后端分离架构：

- **前端**: Vue.js 3 + Element Plus (端口: 3002)
- **后端**: FastAPI (端口: 3001)
- **数据库**: 共享OpenWebUI数据库

## 快速开始

### 1. 环境要求

- **Python**: 3.8+
- **Node.js**: 16+
- **数据库**: PostgreSQL 12+ 或 MySQL 8+ (与OpenWebUI共享)

### 2. 后端部署

```bash
# 进入后端目录
cd backend/administration

# 安装Python依赖
pip install -r requirements.txt

# 配置环境变量 (可选，创建.env文件)
cat > .env << EOF
ADMIN_DB_URL=postgresql://username:password@localhost:5432/openwebui
ADMIN_JWT_SECRET=your-secure-jwt-secret
OPENWEBUI_URL=http://localhost:3000
OPENWEBUI_API_KEY=your-openwebui-api-key
EOF

# 启动后端服务
python main.py
# 或者使用uvicorn (推荐用于生产)
uvicorn main:app --host 0.0.0.0 --port 3001 --reload
```

### 3. 前端部署

```bash
# 进入前端目录
cd frontend/administration

# 安装Node.js依赖
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build

# 预览生产构建
npm run preview
```

## 内置管理员账户

系统启动时会自动创建三个内置管理员账户：

| 角色 | 用户名 | 初始密码 | 权限 |
|------|--------|----------|------|
| 系统管理员 | sys_admin | SysAdmin123! | 用户管理、模型管理、API密钥管理 |
| 安全管理员 | auth_admin | AuthAdmin123! | 安全配置、IP白名单、密码策略 |
| 审计管理员 | audit_admin | AuditAdmin123! | 审计日志查看、统计分析 |

**注意**: 首次登录后请立即修改密码。

## 服务访问

- **前端界面**: http://localhost:3002
- **后端API**: http://localhost:3001
- **API文档**: http://localhost:3001/docs

## 配置说明

### 环境变量配置

```bash
# 数据库配置
ADMIN_DB_URL=postgresql://user:pass@host:port/database

# JWT安全配置
ADMIN_JWT_SECRET=your-secure-secret-key

# OpenWebUI集成
OPENWEBUI_URL=http://your-openwebui-host:port
OPENWEBUI_API_KEY=your-openwebui-api-key

# 安全策略
ADMIN_PASSWORD_EXPIRY_DAYS=90
ADMIN_MAX_LOGIN_ATTEMPTS=5
ADMIN_LOCKOUT_DURATION=1800
```

### 数据库配置

系统会扩展OpenWebUI的数据库架构，添加以下表：

- `admin_config` - 管理配置表
- `admin_api_keys` - API密钥管理表
- 扩展`users`表添加管理员角色字段

## 功能模块

### 系统管理员 (sys_admin)
- **用户管理**: 创建、编辑、删除用户
- **模型管理**: 添加、配置AI模型
- **用户组管理**: 创建和管理用户组
- **API密钥管理**: 生成和管理API密钥

### 安全管理员 (auth_admin)
- **安全配置**: 登录策略、会话管理
- **IP白名单**: 管理允许访问的IP地址
- **密码策略**: 配置密码复杂度要求
- **安全事件**: 监控安全相关事件

### 审计管理员 (audit_admin)
- **审计日志**: 查看所有操作日志
- **统计分析**: 操作频率、用户活跃度分析
- **报告生成**: 生成审计报告
- **数据导出**: 导出日志数据

## API接口

### 认证接口
- `POST /api/auth/login` - 用户登录
- `GET /api/auth/check-password-expiry` - 检查密码过期
- `POST /api/auth/change-password` - 修改密码

### 系统管理员接口
- `GET /api/sys-admin/api-keys` - 获取API密钥列表
- `POST /api/sys-admin/api-keys` - 创建API密钥
- `DELETE /api/sys-admin/api-keys/{id}` - 删除API密钥
- `GET /api/sys-admin/validate-api-key/{api_key}` - 验证API密钥

### 安全管理员接口
- `GET /api/auth-admin/security-config` - 获取安全配置
- `PUT /api/auth-admin/security-config` - 更新安全配置
- `GET /api/auth-admin/ip-whitelist` - 获取IP白名单
- `POST /api/auth-admin/ip-whitelist` - 添加IP到白名单

### 审计管理员接口
- `GET /api/audit-admin/logs` - 获取审计日志
- `GET /api/audit-admin/stats` - 获取统计信息
- `GET /api/audit-admin/operations` - 获取操作监控数据

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查数据库服务是否运行
   - 验证数据库连接字符串
   - 确认数据库用户权限

2. **前端无法访问后端**
   - 检查后端服务是否在端口3001运行
   - 验证CORS配置
   - 检查网络防火墙设置

3. **登录失败**
   - 确认用户名和密码正确
   - 检查JWT密钥配置
   - 查看后端日志获取详细错误信息

4. **OpenWebUI集成失败**
   - 验证OpenWebUI服务是否运行
   - 检查API密钥是否正确
   - 确认网络连通性

### 日志查看

后端日志位于控制台输出，包含：
- 应用启动信息
- 数据库连接状态
- API请求日志
- 错误和异常信息

## 安全建议

1. **生产环境部署**
   - 修改默认的JWT密钥
   - 使用强密码策略
   - 配置HTTPS加密
   - 限制CORS域名

2. **定期维护**
   - 定期更新密码
   - 监控审计日志
   - 备份数据库
   - 更新依赖包

3. **网络配置**
   - 使用防火墙限制访问
   - 配置反向代理
   - 启用SSL/TLS加密

## 技术支持

如有问题，请检查：
1. 后端日志输出
2. 浏览器开发者工具控制台
3. 网络连接状态
4. 数据库连接状态