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
        component: () => import('@/views/SysAdmin/Dashboard.vue'),
        meta: { title: '系统管理', role: 'sys_admin' }
      },
      {
        path: 'sys-admin/api-keys',
        name: 'ApiKeys',
        component: () => import('@/views/SysAdmin/ApiKeys.vue'),
        meta: { title: 'API Key管理', role: 'sys_admin' }
      },
      {
        path: 'sys-admin/users',
        name: 'UserManagement',
        component: () => import('@/views/SysAdmin/UserManagement.vue'),
        meta: { title: '用户管理', role: 'sys_admin' }
      },
      // 安全管理员路由
      {
        path: 'auth-admin',
        name: 'AuthAdmin',
        component: () => import('@/views/AuthAdmin/Dashboard.vue'),
        meta: { title: '安全管理', role: 'auth_admin' }
      },
      {
        path: 'auth-admin/security-config',
        name: 'SecurityConfig',
        component: () => import('@/views/AuthAdmin/SecurityConfig.vue'),
        meta: { title: '安全配置', role: 'auth_admin' }
      },
      {
        path: 'auth-admin/ip-whitelist',
        name: 'IpWhitelist',
        component: () => import('@/views/AuthAdmin/IpWhitelist.vue'),
        meta: { title: 'IP白名单', role: 'auth_admin' }
      },
      // 审计管理员路由
      {
        path: 'audit-admin',
        name: 'AuditAdmin',
        component: () => import('@/views/AuditAdmin/Dashboard.vue'),
        meta: { title: '审计管理', role: 'audit_admin' }
      },
      {
        path: 'audit-admin/logs',
        name: 'AuditLogs',
        component: () => import('@/views/AuditAdmin/AuditLogs.vue'),
        meta: { title: '审计日志', role: 'audit_admin' }
      },
      {
        path: 'audit-admin/statistics',
        name: 'Statistics',
        component: () => import('@/views/AuditAdmin/Statistics.vue'),
        meta: { title: '统计分析', role: 'audit_admin' }
      },
      {
        path: 'audit-admin/operation-monitor',
        name: 'OperationMonitor',
        component: () => import('@/views/AuditAdmin/OperationMonitor.vue'),
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