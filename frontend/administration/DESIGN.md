# 三员管理系统前端设计文档

## 项目概述

### 目标
开发一个简洁精美的Vue.js 3前端应用，为三员管理系统提供用户友好的管理界面。

### 技术栈
- **框架**: Vue.js 3 + Composition API
- **构建工具**: Vite
- **UI组件库**: Element Plus
- **路由**: Vue Router 4
- **状态管理**: Pinia
- **HTTP客户端**: Axios
- **图表库**: ECharts (用于审计统计)
- **样式**: SCSS + Element Plus主题

## 项目结构

```
frontend/administration/
├── public/                   # 静态资源
│   ├── favicon.ico
│   └── index.html
├── src/
│   ├── assets/              # 静态资源
│   │   ├── images/
│   │   └── styles/
│   │       ├── variables.scss
│   │       ├── mixins.scss
│   │       └── global.scss
│   ├── components/          # 通用组件
│   │   ├── common/          # 通用业务组件
│   │   │   ├── PageHeader.vue
│   │   │   ├── DataTable.vue
│   │   │   ├── SearchForm.vue
│   │   │   ├── Pagination.vue
│   │   │   └── ConfirmDialog.vue
│   │   └── layout/          # 布局组件
│   │       ├── AppLayout.vue
│   │       ├── Sidebar.vue
│   │       ├── Header.vue
│   │       └── Footer.vue
│   ├── views/               # 页面组件
│   │   ├── Login.vue        # 登录页面
│   │   ├── Layout.vue       # 主布局
│   │   ├── SysAdmin/        # 系统管理员页面
│   │   │   ├── Dashboard.vue      # 系统概览
│   │   │   ├── ApiKeys.vue        # API Key管理
│   │   │   ├── UserManagement.vue # 用户管理
│   │   │   ├── ModelManagement.vue # 模型管理
│   │   │   └── GroupManagement.vue # 组管理
│   │   ├── AuthAdmin/       # 安全管理员页面
│   │   │   ├── Dashboard.vue      # 安全概览
│   │   │   ├── SecurityConfig.vue # 安全配置
│   │   │   ├── IpWhitelist.vue    # IP白名单
│   │   │   └── PasswordPolicy.vue # 密码策略
│   │   └── AuditAdmin/      # 审计管理员页面
│   │       ├── Dashboard.vue      # 审计概览
│   │       ├── AuditLogs.vue      # 审计日志
│   │       ├── Statistics.vue     # 统计分析
│   │       └── AdminActions.vue   # 管理员操作
│   ├── router/              # 路由配置
│   │   ├── index.js
│   │   ├── routes.js
│   │   └── permission.js    # 路由权限控制
│   ├── store/               # 状态管理
│   │   ├── index.js
│   │   └── modules/
│   │       ├── auth.js      # 认证状态
│   │       ├── app.js       # 应用状态
│   │       ├── sysAdmin.js  # 系统管理员状态
│   │       ├── authAdmin.js # 安全管理员状态
│   │       └── auditAdmin.js # 审计管理员状态
│   ├── api/                 # API接口
│   │   ├── index.js         # API配置
│   │   ├── auth.js          # 认证API
│   │   ├── sysAdmin.js      # 系统管理员API
│   │   ├── authAdmin.js     # 安全管理员API
│   │   └── auditAdmin.js    # 审计管理员API
│   ├── utils/               # 工具函数
│   │   ├── auth.js          # 认证工具
│   │   ├── request.js       # 请求工具
│   │   ├── permission.js    # 权限工具
│   │   ├── date.js          # 日期工具
│   │   └── validate.js      # 验证工具
│   ├── composables/         # 组合式函数
│   │   ├── useApi.js        # API调用
│   │   ├── useTable.js      # 表格操作
│   │   ├── useForm.js       # 表单操作
│   │   └── useChart.js      # 图表操作
│   ├── App.vue              # 根组件
│   └── main.js              # 应用入口
├── package.json
├── vite.config.js
├── .env                     # 环境变量
└── README.md
```

## 页面设计

### 登录页面 (Login.vue)

**设计要点**:
- 简洁的登录表单
- 角色选择（系统管理员/安全管理员/审计管理员）
- 密码修改入口
- 响应式设计

**界面元素**:
- 品牌Logo和标题
- 用户名/密码输入框
- 角色选择下拉框
- 登录按钮
- "忘记密码"链接

### 主布局 (Layout.vue)

**设计要点**:
- 顶部导航栏
- 左侧菜单栏（根据角色动态显示）
- 内容区域
- 页脚信息

**界面元素**:
- 顶部：用户信息、退出登录、系统时间
- 左侧：菜单导航（根据角色显示不同菜单）
- 右侧：主要内容区域
- 底部：版权信息、版本号

### 系统管理员页面

#### 1. 系统概览 (SysAdmin/Dashboard.vue)
- API Key数量统计
- 用户数量统计
- 模型数量统计
- 最近操作记录

#### 2. API Key管理 (SysAdmin/ApiKeys.vue)
- API Key列表（表格展示）
- 创建API Key（表单）
- 编辑API Key（表单）
- 删除API Key（确认对话框）
- API Key验证功能

#### 3. 用户管理 (SysAdmin/UserManagement.vue)
- 用户列表（表格展示）
- 用户详情查看
- 用户状态管理
- 搜索和筛选功能

#### 4. 模型管理 (SysAdmin/ModelManagement.vue)
- 模型列表（表格展示）
- 添加模型（表单）
- 删除模型（确认对话框）
- 模型状态管理

#### 5. 组管理 (SysAdmin/GroupManagement.vue)
- 组列表（表格展示）
- 创建组（表单）
- 编辑组（表单）
- 删除组（确认对话框）

### 安全管理员页面

#### 1. 安全概览 (AuthAdmin/Dashboard.vue)
- 安全配置状态
- 登录失败统计
- IP白名单数量
- 密码策略状态

#### 2. 安全配置 (AuthAdmin/SecurityConfig.vue)
- 登录安全配置表单
- 会话管理配置
- 密码策略配置
- 审计配置

#### 3. IP白名单 (AuthAdmin/IpWhitelist.vue)
- IP白名单列表（表格展示）
- 添加IP地址（表单）
- 删除IP地址（确认对话框）
- IP地址验证

#### 4. 密码策略 (AuthAdmin/PasswordPolicy.vue)
- 密码复杂度要求配置
- 密码过期策略
- 强制密码更换设置
- 历史密码检查

### 审计管理员页面

#### 1. 审计概览 (AuditAdmin/Dashboard.vue)
- 操作统计图表
- 最近审计记录
- 异常操作告警
- 系统健康状态

#### 2. 审计日志 (AuditAdmin/AuditLogs.vue)
- 审计日志列表（表格展示）
- 高级搜索和筛选
- 日志详情查看
- 导出功能

#### 3. 统计分析 (AuditAdmin/Statistics.vue)
- 操作类型分布（饼图）
- 时间趋势分析（折线图）
- 用户活跃度分析（柱状图）
- 异常操作分析

#### 4. 管理员操作 (AuditAdmin/AdminActions.vue)
- 所有管理员操作记录
- 操作详情查看
- 操作统计分析
- 异常操作标记

## 组件设计

### 通用业务组件

#### PageHeader.vue
- 页面标题
- 面包屑导航
- 操作按钮区域

#### DataTable.vue
- 数据表格展示
- 分页功能
- 排序功能
- 筛选功能
- 批量操作

#### SearchForm.vue
- 搜索表单
- 高级筛选
- 重置功能
- 查询按钮

#### Pagination.vue
- 分页控件
- 页面大小选择
- 跳转功能

#### ConfirmDialog.vue
- 确认对话框
- 自定义消息
- 回调函数

### 布局组件

#### AppLayout.vue
- 整体布局容器
- 响应式适配
- 主题切换

#### Sidebar.vue
- 菜单导航
- 折叠功能
- 权限控制

#### Header.vue
- 顶部导航
- 用户信息
- 快捷操作

## 状态管理设计

### Auth Store (auth.js)
```javascript
const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    token: null,
    isAuthenticated: false
  }),

  actions: {
    async login(credentials) {},
    async logout() {},
    async checkAuth() {},
    async changePassword(data) {}
  },

  getters: {
    userRole: (state) => state.user?.role,
    userName: (state) => state.user?.username,
    displayName: (state) => state.user?.display_name
  }
});
```

### SysAdmin Store (sysAdmin.js)
```javascript
const useSysAdminStore = defineStore('sysAdmin', {
  state: () => ({
    apiKeys: [],
    users: [],
    models: [],
    groups: []
  }),

  actions: {
    async fetchApiKeys() {},
    async createApiKey(data) {},
    async deleteApiKey(id) {},
    async validateApiKey(apiKey) {},
    async fetchUsers() {},
    async fetchModels() {},
    async fetchGroups() {}
  }
});
```

## API接口设计

### API配置 (api/index.js)
```javascript
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api',
  timeout: 10000
});

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('admin_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// 响应拦截器
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response?.status === 401) {
      // 处理认证失败
      localStorage.removeItem('admin_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

### 认证API (api/auth.js)
```javascript
import api from './index';

export const authApi = {
  login: (credentials) => api.post('/auth/login', credentials),
  checkPasswordExpiry: () => api.get('/auth/check-password-expiry'),
  changePassword: (data) => api.post('/auth/change-password', data),
  logout: () => api.post('/auth/logout')
};
```

## 路由设计

### 路由配置 (router/routes.js)
```javascript
const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    component: () => import('@/views/Layout.vue'),
    meta: { requiresAuth: true },
    children: [
      // 系统管理员路由
      {
        path: 'sys-admin',
        name: 'SysAdmin',
        component: () => import('@/views/SysAdmin/Dashboard.vue'),
        meta: { role: 'sys_admin' }
      },
      {
        path: 'sys-admin/api-keys',
        name: 'ApiKeys',
        component: () => import('@/views/SysAdmin/ApiKeys.vue'),
        meta: { role: 'sys_admin' }
      },
      // 安全管理员路由
      {
        path: 'auth-admin',
        name: 'AuthAdmin',
        component: () => import('@/views/AuthAdmin/Dashboard.vue'),
        meta: { role: 'auth_admin' }
      },
      // 审计管理员路由
      {
        path: 'audit-admin',
        name: 'AuditAdmin',
        component: () => import('@/views/AuditAdmin/Dashboard.vue'),
        meta: { role: 'audit_admin' }
      }
    ]
  }
];
```

### 权限控制 (router/permission.js)
```javascript
export function hasPermission(route, userRole) {
  if (route.meta?.role) {
    return route.meta.role === userRole;
  }
  return true;
}
```

## 样式设计

### 主题色彩
- **主色调**: #409EFF (Element Plus 默认蓝)
- **成功色**: #67C23A
- **警告色**: #E6A23C
- **危险色**: #F56C6C
- **信息色**: #909399

### 响应式断点
- **xs**: < 768px
- **sm**: ≥ 768px
- **md**: ≥ 992px
- **lg**: ≥ 1200px
- **xl**: ≥ 1920px

## 开发规范

### 代码规范
- 使用ESLint + Prettier
- 组件命名使用PascalCase
- 文件命名使用kebab-case
- 变量命名使用camelCase

### 组件开发规范
- 使用Composition API
- 组件props使用TypeScript类型定义
- 事件使用emit规范
- 插槽使用具名插槽

### 样式规范
- 使用SCSS预处理器
- BEM命名规范
- 组件样式作用域
- 主题变量统一管理

## 性能优化

### 代码分割
- 路由懒加载
- 组件异步加载
- 第三方库按需引入

### 缓存策略
- API响应缓存
- 本地存储优化
- 图片懒加载

### 构建优化
- Tree Shaking
- 代码压缩
- 资源压缩

## 测试策略

### 单元测试
- 组件测试 (Vitest + Vue Test Utils)
- 工具函数测试
- Store测试

### 集成测试
- 页面功能测试
- API集成测试
- 权限控制测试

### E2E测试
- 用户流程测试
- 跨浏览器测试
- 性能测试

## 部署配置

### 环境变量
```bash
# 开发环境
VITE_API_BASE_URL=http://localhost:3001/api
VITE_APP_TITLE=三员管理系统

# 生产环境
VITE_API_BASE_URL=https://your-domain.com/api
VITE_APP_TITLE=三员管理系统
```

### 构建命令
```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "test": "vitest",
    "lint": "eslint . --ext .vue,.js,.jsx,.cjs,.mjs --fix --ignore-path .gitignore"
  }
}
```

## 用户体验设计

### 交互设计
- 加载状态提示
- 错误处理提示
- 操作确认对话框
- 表单验证反馈

### 可访问性
- 键盘导航支持
- 屏幕阅读器支持
- 颜色对比度
- 字体大小适配

### 国际化
- 多语言支持
- 日期时间格式化
- 数字格式化

这个设计文档提供了完整的前端架构和实现方案，确保开发出简洁精美的三员管理系统前端界面。