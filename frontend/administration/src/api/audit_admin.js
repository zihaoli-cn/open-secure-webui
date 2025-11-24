import api from './index.js'

// 审计日志管理API
export const auditLogsApi = {
  // 获取审计日志列表
  getAuditLogs: (params = {}) => {
    return api.get('/api/audit-admin/logs', { params })
  },

  // 获取审计日志详情
  getAuditLogDetail: (logId) => {
    return api.get(`/api/audit-admin/logs/${logId}`)
  },

  // 搜索审计日志
  searchAuditLogs: (searchParams) => {
    return api.post('/api/audit-admin/logs/search', searchParams)
  },

  // 导出审计日志
  exportAuditLogs: (exportParams) => {
    return api.post('/api/audit-admin/logs/export', exportParams, { responseType: 'blob' })
  },

  // 批量删除审计日志
  batchDeleteAuditLogs: (logIds) => {
    return api.post('/api/audit-admin/logs/batch-delete', { log_ids: logIds })
  },

  // 清理过期审计日志
  cleanupExpiredLogs: () => {
    return api.post('/api/audit-admin/logs/cleanup')
  }
}

// 统计分析API
export const statisticsApi = {
  // 获取审计统计概览
  getAuditOverview: () => {
    return api.get('/api/audit-admin/statistics/overview')
  },

  // 获取操作类型统计
  getOperationTypeStats: (params = {}) => {
    return api.get('/api/audit-admin/statistics/operation-types', { params })
  },

  // 获取用户活动统计
  getUserActivityStats: (params = {}) => {
    return api.get('/api/audit-admin/statistics/user-activity', { params })
  },

  // 获取时间趋势统计
  getTimeTrendStats: (params = {}) => {
    return api.get('/api/audit-admin/statistics/time-trend', { params })
  },

  // 获取风险事件统计
  getRiskEventStats: (params = {}) => {
    return api.get('/api/audit-admin/statistics/risk-events', { params })
  },

  // 生成审计报告
  generateAuditReport: (reportParams) => {
    return api.post('/api/audit-admin/statistics/generate-report', reportParams)
  }
}

// 实时监控API
export const realtimeMonitorApi = {
  // 获取实时操作流
  getRealtimeOperations: (params = {}) => {
    return api.get('/api/audit-admin/monitor/realtime-operations', { params })
  },

  // 获取活跃用户监控
  getActiveUsersMonitor: () => {
    return api.get('/api/audit-admin/monitor/active-users')
  },

  // 获取系统健康状态
  getSystemHealthStatus: () => {
    return api.get('/api/audit-admin/monitor/system-health')
  },

  // 获取异常操作告警
  getAnomalyAlerts: (params = {}) => {
    return api.get('/api/audit-admin/monitor/anomaly-alerts', { params })
  },

  // 订阅实时事件
  subscribeRealtimeEvents: () => {
    return api.get('/api/audit-admin/monitor/subscribe')
  },

  // 取消订阅实时事件
  unsubscribeRealtimeEvents: (subscriptionId) => {
    return api.post(`/api/audit-admin/monitor/unsubscribe/${subscriptionId}`)
  }
}

// 告警管理API
export const alertsApi = {
  // 获取告警列表
  getAlerts: (params = {}) => {
    return api.get('/api/audit-admin/alerts', { params })
  },

  // 获取告警详情
  getAlertDetail: (alertId) => {
    return api.get(`/api/audit-admin/alerts/${alertId}`)
  },

  // 创建告警规则
  createAlertRule: (ruleData) => {
    return api.post('/api/audit-admin/alerts/rules', ruleData)
  },

  // 更新告警规则
  updateAlertRule: (ruleId, ruleData) => {
    return api.put(`/api/audit-admin/alerts/rules/${ruleId}`, ruleData)
  },

  // 删除告警规则
  deleteAlertRule: (ruleId) => {
    return api.delete(`/api/audit-admin/alerts/rules/${ruleId}`)
  },

  // 获取告警规则列表
  getAlertRules: (params = {}) => {
    return api.get('/api/audit-admin/alerts/rules', { params })
  },

  // 标记告警为已处理
  markAlertAsResolved: (alertId) => {
    return api.post(`/api/audit-admin/alerts/${alertId}/resolve`)
  },

  // 批量处理告警
  batchResolveAlerts: (alertIds) => {
    return api.post('/api/audit-admin/alerts/batch-resolve', { alert_ids: alertIds })
  }
}

// 审计配置API
export const auditConfigApi = {
  // 获取审计配置
  getAuditConfig: () => {
    return api.get('/api/audit-admin/config')
  },

  // 更新审计配置
  updateAuditConfig: (configData) => {
    return api.put('/api/audit-admin/config', configData)
  },

  // 重置审计配置
  resetAuditConfig: () => {
    return api.post('/api/audit-admin/config/reset')
  },

  // 获取审计保留策略
  getRetentionPolicies: () => {
    return api.get('/api/audit-admin/config/retention-policies')
  },

  // 更新审计保留策略
  updateRetentionPolicies: (policies) => {
    return api.put('/api/audit-admin/config/retention-policies', policies)
  }
}

// 默认导出所有API
export default {
  auditLogs: auditLogsApi,
  statistics: statisticsApi,
  realtimeMonitor: realtimeMonitorApi,
  alerts: alertsApi,
  auditConfig: auditConfigApi
}