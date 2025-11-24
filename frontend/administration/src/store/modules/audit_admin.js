import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import auditAdminApi from '@/api/audit_admin'

export const useAuditAdminStore = defineStore('audit_admin', () => {
  // 审计日志管理状态
  const auditLogs = ref([])
  const auditLogsLoading = ref(false)
  const auditLogsTotal = ref(0)
  const auditLogsPage = ref(1)
  const auditLogsPageSize = ref(10)

  // 统计分析状态
  const statistics = ref({})
  const statisticsLoading = ref(false)
  const statisticsOverview = ref({})
  const operationTypeStats = ref([])
  const userActivityStats = ref([])
  const timeTrendStats = ref([])

  // 实时监控状态
  const realtimeOperations = ref([])
  const realtimeLoading = ref(false)
  const activeUsers = ref([])
  const systemHealth = ref({})
  const anomalyAlerts = ref([])

  // 告警管理状态
  const alerts = ref([])
  const alertsLoading = ref(false)
  const alertsTotal = ref(0)
  const alertsPage = ref(1)
  const alertsPageSize = ref(10)
  const alertRules = ref([])

  // 审计配置状态
  const auditConfig = ref({})
  const configLoading = ref(false)

  // 计算属性
  const auditStats = computed(() => {
    return {
      totalLogs: auditLogsTotal.value,
      todayLogs: auditLogs.value.filter(log => {
        const logDate = new Date(log.created_at)
        const today = new Date()
        return logDate.toDateString() === today.toDateString()
      }).length,
      criticalAlerts: alerts.value.filter(alert => alert.severity === 'critical').length,
      activeUsers: activeUsers.value.length
    }
  })

  const operationStats = computed(() => {
    return {
      total: operationTypeStats.value.reduce((total, stat) => total + stat.count, 0),
      byType: operationTypeStats.value.reduce((acc, stat) => {
        acc[stat.operation_type] = stat.count
        return acc
      }, {})
    }
  })

  const alertStats = computed(() => {
    return {
      total: alertsTotal.value,
      critical: alerts.value.filter(alert => alert.severity === 'critical').length,
      warning: alerts.value.filter(alert => alert.severity === 'warning').length,
      info: alerts.value.filter(alert => alert.severity === 'info').length
    }
  })

  // 审计日志管理操作
  const loadAuditLogs = async (params = {}) => {
    try {
      auditLogsLoading.value = true
      const response = await auditAdminApi.auditLogs.getAuditLogs({
        page: auditLogsPage.value,
        size: auditLogsPageSize.value,
        ...params
      })
      auditLogs.value = response.data || []
      auditLogsTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载审计日志失败:', error)
      throw error
    } finally {
      auditLogsLoading.value = false
    }
  }

  const searchAuditLogs = async (searchParams) => {
    try {
      auditLogsLoading.value = true
      const response = await auditAdminApi.auditLogs.searchAuditLogs(searchParams)
      auditLogs.value = response.data || []
      auditLogsTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('搜索审计日志失败:', error)
      throw error
    } finally {
      auditLogsLoading.value = false
    }
  }

  const getAuditLogDetail = async (logId) => {
    try {
      const response = await auditAdminApi.auditLogs.getAuditLogDetail(logId)
      return response
    } catch (error) {
      console.error('获取审计日志详情失败:', error)
      throw error
    }
  }

  const exportAuditLogs = async (exportParams) => {
    try {
      const response = await auditAdminApi.auditLogs.exportAuditLogs(exportParams)
      return response
    } catch (error) {
      console.error('导出审计日志失败:', error)
      throw error
    }
  }

  const batchDeleteAuditLogs = async (logIds) => {
    try {
      const response = await auditAdminApi.auditLogs.batchDeleteAuditLogs(logIds)
      await loadAuditLogs()
      return response
    } catch (error) {
      console.error('批量删除审计日志失败:', error)
      throw error
    }
  }

  // 统计分析操作
  const loadStatisticsOverview = async () => {
    try {
      statisticsLoading.value = true
      const response = await auditAdminApi.statistics.getAuditOverview()
      statisticsOverview.value = response.data || {}
      return response
    } catch (error) {
      console.error('加载统计概览失败:', error)
      throw error
    } finally {
      statisticsLoading.value = false
    }
  }

  const loadOperationTypeStats = async (params = {}) => {
    try {
      const response = await auditAdminApi.statistics.getOperationTypeStats(params)
      operationTypeStats.value = response.data || []
      return response
    } catch (error) {
      console.error('加载操作类型统计失败:', error)
      throw error
    }
  }

  const loadUserActivityStats = async (params = {}) => {
    try {
      const response = await auditAdminApi.statistics.getUserActivityStats(params)
      userActivityStats.value = response.data || []
      return response
    } catch (error) {
      console.error('加载用户活动统计失败:', error)
      throw error
    }
  }

  const loadTimeTrendStats = async (params = {}) => {
    try {
      const response = await auditAdminApi.statistics.getTimeTrendStats(params)
      timeTrendStats.value = response.data || []
      return response
    } catch (error) {
      console.error('加载时间趋势统计失败:', error)
      throw error
    }
  }

  const generateAuditReport = async (reportParams) => {
    try {
      const response = await auditAdminApi.statistics.generateAuditReport(reportParams)
      return response
    } catch (error) {
      console.error('生成审计报告失败:', error)
      throw error
    }
  }

  // 实时监控操作
  const loadRealtimeOperations = async (params = {}) => {
    try {
      realtimeLoading.value = true
      const response = await auditAdminApi.realtimeMonitor.getRealtimeOperations(params)
      realtimeOperations.value = response.data || []
      return response
    } catch (error) {
      console.error('加载实时操作失败:', error)
      throw error
    } finally {
      realtimeLoading.value = false
    }
  }

  const loadActiveUsersMonitor = async () => {
    try {
      const response = await auditAdminApi.realtimeMonitor.getActiveUsersMonitor()
      activeUsers.value = response.data || []
      return response
    } catch (error) {
      console.error('加载活跃用户监控失败:', error)
      throw error
    }
  }

  const loadSystemHealthStatus = async () => {
    try {
      const response = await auditAdminApi.realtimeMonitor.getSystemHealthStatus()
      systemHealth.value = response.data || {}
      return response
    } catch (error) {
      console.error('加载系统健康状态失败:', error)
      throw error
    }
  }

  const loadAnomalyAlerts = async (params = {}) => {
    try {
      const response = await auditAdminApi.realtimeMonitor.getAnomalyAlerts(params)
      anomalyAlerts.value = response.data || []
      return response
    } catch (error) {
      console.error('加载异常告警失败:', error)
      throw error
    }
  }

  // 告警管理操作
  const loadAlerts = async (params = {}) => {
    try {
      alertsLoading.value = true
      const response = await auditAdminApi.alerts.getAlerts({
        page: alertsPage.value,
        size: alertsPageSize.value,
        ...params
      })
      alerts.value = response.data || []
      alertsTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载告警列表失败:', error)
      throw error
    } finally {
      alertsLoading.value = false
    }
  }

  const getAlertDetail = async (alertId) => {
    try {
      const response = await auditAdminApi.alerts.getAlertDetail(alertId)
      return response
    } catch (error) {
      console.error('获取告警详情失败:', error)
      throw error
    }
  }

  const markAlertAsResolved = async (alertId) => {
    try {
      const response = await auditAdminApi.alerts.markAlertAsResolved(alertId)
      await loadAlerts()
      return response
    } catch (error) {
      console.error('标记告警为已处理失败:', error)
      throw error
    }
  }

  const batchResolveAlerts = async (alertIds) => {
    try {
      const response = await auditAdminApi.alerts.batchResolveAlerts(alertIds)
      await loadAlerts()
      return response
    } catch (error) {
      console.error('批量处理告警失败:', error)
      throw error
    }
  }

  const loadAlertRules = async (params = {}) => {
    try {
      const response = await auditAdminApi.alerts.getAlertRules(params)
      alertRules.value = response.data || []
      return response
    } catch (error) {
      console.error('加载告警规则失败:', error)
      throw error
    }
  }

  const createAlertRule = async (ruleData) => {
    try {
      const response = await auditAdminApi.alerts.createAlertRule(ruleData)
      await loadAlertRules()
      return response
    } catch (error) {
      console.error('创建告警规则失败:', error)
      throw error
    }
  }

  const updateAlertRule = async (ruleId, ruleData) => {
    try {
      const response = await auditAdminApi.alerts.updateAlertRule(ruleId, ruleData)
      await loadAlertRules()
      return response
    } catch (error) {
      console.error('更新告警规则失败:', error)
      throw error
    }
  }

  const deleteAlertRule = async (ruleId) => {
    try {
      const response = await auditAdminApi.alerts.deleteAlertRule(ruleId)
      await loadAlertRules()
      return response
    } catch (error) {
      console.error('删除告警规则失败:', error)
      throw error
    }
  }

  // 审计配置操作
  const loadAuditConfig = async () => {
    try {
      configLoading.value = true
      const response = await auditAdminApi.auditConfig.getAuditConfig()
      auditConfig.value = response.data || {}
      return response
    } catch (error) {
      console.error('加载审计配置失败:', error)
      throw error
    } finally {
      configLoading.value = false
    }
  }

  const updateAuditConfig = async (configData) => {
    try {
      const response = await auditAdminApi.auditConfig.updateAuditConfig(configData)
      await loadAuditConfig()
      return response
    } catch (error) {
      console.error('更新审计配置失败:', error)
      throw error
    }
  }

  // 重置状态
  const reset = () => {
    auditLogs.value = []
    auditLogsLoading.value = false
    auditLogsTotal.value = 0
    auditLogsPage.value = 1
    auditLogsPageSize.value = 10

    statistics.value = {}
    statisticsLoading.value = false
    statisticsOverview.value = {}
    operationTypeStats.value = []
    userActivityStats.value = []
    timeTrendStats.value = []

    realtimeOperations.value = []
    realtimeLoading.value = false
    activeUsers.value = []
    systemHealth.value = {}
    anomalyAlerts.value = []

    alerts.value = []
    alertsLoading.value = false
    alertsTotal.value = 0
    alertsPage.value = 1
    alertsPageSize.value = 10
    alertRules.value = []

    auditConfig.value = {}
    configLoading.value = false
  }

  return {
    // 状态
    auditLogs,
    auditLogsLoading,
    auditLogsTotal,
    auditLogsPage,
    auditLogsPageSize,

    statistics,
    statisticsLoading,
    statisticsOverview,
    operationTypeStats,
    userActivityStats,
    timeTrendStats,

    realtimeOperations,
    realtimeLoading,
    activeUsers,
    systemHealth,
    anomalyAlerts,

    alerts,
    alertsLoading,
    alertsTotal,
    alertsPage,
    alertsPageSize,
    alertRules,

    auditConfig,
    configLoading,

    // 计算属性
    auditStats,
    operationStats,
    alertStats,

    // 操作
    loadAuditLogs,
    searchAuditLogs,
    getAuditLogDetail,
    exportAuditLogs,
    batchDeleteAuditLogs,

    loadStatisticsOverview,
    loadOperationTypeStats,
    loadUserActivityStats,
    loadTimeTrendStats,
    generateAuditReport,

    loadRealtimeOperations,
    loadActiveUsersMonitor,
    loadSystemHealthStatus,
    loadAnomalyAlerts,

    loadAlerts,
    getAlertDetail,
    markAlertAsResolved,
    batchResolveAlerts,
    loadAlertRules,
    createAlertRule,
    updateAlertRule,
    deleteAlertRule,

    loadAuditConfig,
    updateAuditConfig,

    reset
  }
})