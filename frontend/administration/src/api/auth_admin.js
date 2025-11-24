import api from './index.js'

// 安全配置管理API
export const securityConfigApi = {
  // 获取安全配置
  getSecurityConfig: () => {
    return api.get('/auth-admin/security-config')
  },

  // 更新安全配置
  updateSecurityConfig: (configData) => {
    return api.put('/auth-admin/security-config', configData)
  },

  // 获取安全统计信息
  getSecurityStats: () => {
    return api.get('/auth-admin/stats')
  },

  // 获取最近安全事件
  getRecentSecurityEvents: (limit = 10) => {
    return api.get('/auth-admin/security-events', { params: { limit } })
  }
}

// IP白名单管理API
export const ipWhitelistApi = {
  // 获取IP白名单列表
  getIpWhitelist: (params = {}) => {
    return api.get('/auth-admin/ip-whitelist', { params })
  },

  // 添加IP地址到白名单
  addIpAddress: (ipData) => {
    return api.post('/auth-admin/ip-whitelist', ipData)
  },

  // 更新IP地址
  updateIpAddress: (ipId, ipData) => {
    return api.put(`/auth-admin/ip-whitelist/${ipId}`, ipData)
  },

  // 删除IP地址
  deleteIpAddress: (ipId) => {
    return api.delete(`/auth-admin/ip-whitelist/${ipId}`)
  },

  // 启用IP地址
  enableIpAddress: (ipId) => {
    return api.patch(`/auth-admin/ip-whitelist/${ipId}/enable`)
  },

  // 禁用IP地址
  disableIpAddress: (ipId) => {
    return api.patch(`/auth-admin/ip-whitelist/${ipId}/disable`)
  },

  // 批量启用/禁用IP地址
  batchToggleIpAddresses: (ipIds, enabled) => {
    return api.patch('/auth-admin/ip-whitelist/batch-toggle', {
      ip_ids: ipIds,
      enabled
    })
  },

  // 验证IP格式
  validateIpFormat: (ipAddress) => {
    return api.post('/auth-admin/ip-whitelist/validate', { ip_address: ipAddress })
  }
}

// 密码策略管理API
export const passwordPolicyApi = {
  // 获取密码策略
  getPasswordPolicy: () => {
    return api.get('/auth-admin/password-policy')
  },

  // 更新密码策略
  updatePasswordPolicy: (policyData) => {
    return api.put('/auth-admin/password-policy', policyData)
  },

  // 测试密码复杂度
  testPasswordComplexity: (password) => {
    return api.post('/auth-admin/password-policy/test-complexity', { password })
  },

  // 生成密码策略报告
  generatePolicyReport: () => {
    return api.get('/auth-admin/password-policy/report')
  },

  // 重置密码策略为默认值
  resetToDefaults: () => {
    return api.post('/auth-admin/password-policy/reset-defaults')
  }
}

// 会话管理API
export const sessionApi = {
  // 获取会话统计
  getSessionStats: () => {
    return api.get('/auth-admin/sessions/stats')
  },

  // 获取活跃会话列表
  getActiveSessions: (params = {}) => {
    return api.get('/auth-admin/sessions/active', { params })
  },

  // 强制结束会话
  terminateSession: (sessionId) => {
    return api.delete(`/auth-admin/sessions/${sessionId}`)
  },

  // 批量结束会话
  batchTerminateSessions: (sessionIds) => {
    return api.post('/auth-admin/sessions/batch-terminate', { session_ids: sessionIds })
  }
}

export default {
  securityConfig: securityConfigApi,
  ipWhitelist: ipWhitelistApi,
  passwordPolicy: passwordPolicyApi,
  session: sessionApi
}