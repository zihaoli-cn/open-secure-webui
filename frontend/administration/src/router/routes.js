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
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: '概览' }
      },
      // 系统管理员路由
      {
        path: 'sys-admin',
        name: 'SysAdmin',
        component: () => import('@/views/sys_admin/Dashboard.vue'),
        meta: { title: '系统管理', role: 'sys_admin' }
      },
      {
        path: 'sys-admin/api-keys',
        name: 'ApiKeys',
        component: () => import('@/views/sys_admin/ApiKeys.vue'),
        meta: { title: 'API Key管理', role: 'sys_admin' }
      },
      {
        path: 'sys-admin/users',
        name: 'UserManagement',
        component: () => import('@/views/sys_admin/UserManagement.vue'),
        meta: { title: '用户管理', role: 'sys_admin' }
      },
      {
        path: 'sys-admin/models',
        name: 'ModelManagement',
        component: () => import('@/views/sys_admin/ModelManagement.vue'),
        meta: { title: '模型管理', role: 'sys_admin' }
      },
      {
        path: 'sys-admin/groups',
        name: 'GroupManagement',
        component: () => import('@/views/sys_admin/GroupManagement.vue'),
        meta: { title: '分组管理', role: 'sys_admin' }
      },
      // 安全管理员路由
      {
        path: 'auth-admin',
        name: 'AuthAdmin',
        component: () => import('@/views/auth_admin/Dashboard.vue'),
        meta: { title: '安全管理', role: 'auth_admin' }
      },
      {
        path: 'auth-admin/security-config',
        name: 'SecurityConfig',
        component: () => import('@/views/auth_admin/SecurityConfig.vue'),
        meta: { title: '安全配置', role: 'auth_admin' }
      },
      {
        path: 'auth-admin/ip-whitelist',
        name: 'IpWhitelist',
        component: () => import('@/views/auth_admin/IpWhitelist.vue'),
        meta: { title: 'IP白名单', role: 'auth_admin' }
      },
      {
        path: 'auth-admin/password-policy',
        name: 'PasswordPolicy',
        component: () => import('@/views/auth_admin/PasswordPolicy.vue'),
        meta: { title: '密码策略', role: 'auth_admin' }
      },
      // 审计管理员路由
      {
        path: 'audit-admin',
        name: 'AuditAdmin',
        component: () => import('@/views/audit_admin/Dashboard.vue'),
        meta: { title: '审计管理', role: 'audit_admin' }
      },
      {
        path: 'audit-admin/logs',
        name: 'AuditLogs',
        component: () => import('@/views/audit_admin/AuditLogs.vue'),
        meta: { title: '审计日志', role: 'audit_admin' }
      },
      {
        path: 'audit-admin/statistics',
        name: 'Statistics',
        component: () => import('@/views/audit_admin/Statistics.vue'),
        meta: { title: '统计分析', role: 'audit_admin' }
      },
      {
        path: 'audit-admin/operation-monitor',
        name: 'OperationMonitor',
        component: () => import('@/views/audit_admin/OperationMonitor.vue'),
        meta: { title: '实时监控', role: 'audit_admin' }
      }
    ]
  },
  {
    path: '/unauthorized',
    name: 'Unauthorized',
    component: () => import('@/views/Unauthorized.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/NotFound.vue'),
    meta: { requiresAuth: false }
  }
]

export default routes