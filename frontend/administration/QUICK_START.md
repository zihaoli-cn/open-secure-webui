# 前端快速启动指南

## 快速开始

### 1. 安装依赖

```bash
# 进入前端目录
cd frontend/administration

# 安装所有依赖包
npm install
```

### 2. 启动开发服务器

```bash
# 启动开发服务器 (端口: 3002)
npm run dev
```

### 3. 访问应用

打开浏览器访问: http://localhost:3002

## 开发环境配置

### 环境变量

创建 `.env` 文件进行环境配置：

```bash
# API基础URL
VITE_API_BASE_URL=http://localhost:3001/api

# 应用标题
VITE_APP_TITLE=三员管理系统

# 开发模式
VITE_DEV_MODE=true
```

### 开发命令

```bash
# 开发模式 (热重载)
npm run dev

# 构建生产版本
npm run build

# 预览生产构建
npm run preview

# 运行测试
npm run test

# 代码检查
npm run lint
```

## 项目结构

```
frontend/administration/
├── src/
│   ├── views/           # 页面组件
│   │   ├── sys_admin/   # 系统管理员页面
│   │   ├── auth_admin/  # 安全管理员页面
│   │   └── audit_admin/ # 审计管理员页面
│   ├── components/      # 可复用组件
│   ├── store/           # 状态管理
│   ├── api/             # API接口
│   ├── router/          # 路由配置
│   └── utils/           # 工具函数
├── package.json
└── vite.config.js
```

## 内置账户

使用以下账户登录：

| 角色 | 用户名 | 密码 |
|------|--------|------|
| 系统管理员 | sys_admin | SysAdmin123! |
| 安全管理员 | auth_admin | AuthAdmin123! |
| 审计管理员 | audit_admin | AuditAdmin123! |

## 功能模块

### 系统管理员界面
- 用户管理
- 模型管理
- 用户组管理
- API密钥管理

### 安全管理员界面
- 安全配置
- IP白名单
- 密码策略
- 会话管理

### 审计管理员界面
- 审计日志
- 统计分析
- 操作监控
- 报告生成

## 故障排除

### 常见问题

1. **依赖安装失败**
   ```bash
   # 清除缓存重新安装
   npm cache clean --force
   rm -rf node_modules package-lock.json
   npm install
   ```

2. **端口被占用**
   ```bash
   # 查找占用端口的进程
   lsof -i :3002
   # 或者使用其他端口
   npm run dev -- --port 3003
   ```

3. **API连接失败**
   - 确认后端服务在端口3001运行
   - 检查网络连接
   - 查看浏览器控制台错误信息

### 开发工具

- **Vue DevTools**: 浏览器扩展，用于调试Vue应用
- **Element Plus**: UI组件库文档
- **Vite**: 构建工具配置

## 生产部署

```bash
# 构建生产版本
npm run build

# 预览构建结果
npm run preview

# 部署到Web服务器
# 将dist目录内容部署到Web服务器根目录
```

## 技术支持

- 查看浏览器控制台错误信息
- 检查网络请求状态
- 验证后端服务状态
- 查看Vite开发服务器日志