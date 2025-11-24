# 三员管理系统前端部署指南

## 部署方式

### 方式1：Docker Compose 部署（推荐）

使用项目根目录的 `docker-compose.admin.yml`：

```bash
# 在项目根目录执行
docker-compose -f docker-compose.admin.yml up -d
```

前端会自动通过 nginx 代理访问后端服务。

---

### 方式2：独立部署（前后端分离）

#### 2.1 后端部署

```bash
cd backend/administration
./start.sh
```

后端将在 `http://0.0.0.0:3001` 启动。

#### 2.2 前端部署

**选项A：使用 Vite 开发服务器（开发环境）**

```bash
cd frontend/administration
npm install
npm run dev
```

前端将在 `http://localhost:3002` 启动，自动连接到 `http://localhost:3001/api`。

**选项B：构建并使用 Nginx（生产环境）**

1. **构建前端**

```bash
cd frontend/administration
npm install
npm run build
```

2. **配置 Nginx**

复制构建产物到 nginx 目录：

```bash
sudo cp -r dist/* /usr/share/nginx/html/
```

复制 nginx 配置：

```bash
sudo cp nginx-standalone.conf /etc/nginx/conf.d/admin.conf
```

3. **重启 Nginx**

```bash
sudo nginx -t
sudo systemctl restart nginx
```

前端将在 `http://your-server-ip` 访问，API 请求会自动代理到 `http://127.0.0.1:3001/api`。

---

### 方式3：直接访问后端（无 Nginx 代理）

如果不使用 nginx 代理，需要配置前端直接访问后端。

1. **修改环境变量**

创建 `.env.production.local` 文件：

```bash
# 替换为你的后端地址
VITE_API_BASE_URL=http://your-server-ip:3001/api
```

2. **构建前端**

```bash
npm run build
```

3. **部署构建产物**

将 `dist/` 目录部署到任何静态文件服务器（nginx、Apache、CDN等）。

---

## 环境变量说明

### `.env` - 开发环境

```bash
# API配置（开发环境）
VITE_API_BASE_URL=http://localhost:3001/api

# 应用配置
VITE_APP_TITLE=三员管理系统
```

### `.env.production` - 生产环境

```bash
# API配置
# 留空使用相对路径 /api（通过nginx代理）
VITE_API_BASE_URL=

# 如果不使用nginx代理，配置完整URL
# VITE_API_BASE_URL=http://your-server-ip:3001/api

# 应用配置
VITE_APP_TITLE=三员管理系统
```

---

## API 配置逻辑

前端会按以下优先级选择 API 地址：

1. **环境变量** `VITE_API_BASE_URL`（如果设置）
2. **生产环境**：使用相对路径 `/api`（通过 nginx 代理）
3. **开发环境**：使用 `http://localhost:3001/api`

---

## Nginx 配置说明

### Docker 部署（nginx.conf）

```nginx
location /api {
    proxy_pass http://admin-backend:3001;  # Docker服务名
    ...
}
```

### 独立部署（nginx-standalone.conf）

```nginx
location /api {
    proxy_pass http://127.0.0.1:3001;  # 本地后端
    ...
}
```

---

## 常见问题

### 1. 前端无法连接后端（ERR_CONNECTION_REFUSED）

**原因**：前端尝试连接 `localhost:3001`，但后端不在本地。

**解决方案**：

- **方案A**（推荐）：使用 nginx 代理
  - 复制 `nginx-standalone.conf` 到 nginx 配置目录
  - 重启 nginx
  - 前端会通过 `/api` 访问后端

- **方案B**：配置环境变量
  - 创建 `.env.production.local`
  - 设置 `VITE_API_BASE_URL=http://your-server-ip:3001/api`
  - 重新构建前端

### 2. CORS 错误

**原因**：前端直接访问后端，但后端没有配置 CORS。

**解决方案**：

- 使用 nginx 代理（推荐）
- 或在后端 `main.py` 中添加 CORS 配置：

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 生产环境应限制具体域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 3. 生产环境 API 路径错误

**检查**：

1. 打开浏览器开发者工具 → Network 标签
2. 查看 API 请求的完整 URL
3. 确认是否正确

**调试**：

在浏览器控制台执行：

```javascript
console.log(import.meta.env.VITE_API_BASE_URL)
console.log(import.meta.env.PROD)
```

---

## 端口说明

- **后端**：3001
- **前端开发服务器**：3002
- **前端生产环境（nginx）**：80 或 443

---

## 安全建议

1. **生产环境**：使用 HTTPS
2. **CORS**：限制允许的域名
3. **Nginx**：启用安全头（已在配置中包含）
4. **防火墙**：只开放必要的端口

---

## 快速排查

如果前端无法连接后端，按以下步骤排查：

1. **确认后端运行**：
   ```bash
   curl http://localhost:3001/health
   ```

2. **确认前端构建正确**：
   ```bash
   # 查看构建产物中的 API 配置
   grep -r "baseURL" dist/assets/*.js
   ```

3. **确认 nginx 配置**：
   ```bash
   sudo nginx -t
   curl http://localhost/api/health
   ```

4. **查看浏览器控制台**：
   - 打开开发者工具
   - 查看 Network 标签
   - 检查 API 请求的 URL 和状态

---

**部署完成后，访问 `http://your-server-ip` 即可使用三员管理系统！**
