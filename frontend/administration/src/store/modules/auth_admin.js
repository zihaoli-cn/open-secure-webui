import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import authAdminApi from '@/api/auth_admin'

export const useAuthAdminStore = defineStore('auth_admin', () => {
  // 安全配置状态
  const securityConfig = ref({})
  const securityConfigLoading = ref(false)

  // IP白名单状态
  const ipWhitelist = ref([])
  const ipWhitelistLoading = ref(false)
  const ipWhitelistTotal = ref(0)
  const ipWhitelistPage = ref(1)
  const ipWhitelistPageSize = ref(10)

  // 密码策略状态
  const passwordPolicy = ref({})
  const passwordPolicyLoading = ref(false)

  // 会话管理状态
  const activeSessions = ref([])
  const sessionsLoading = ref(false)
  const sessionsTotal = ref(0)
  const sessionsPage = ref(1)
  const sessionsPageSize = ref(10)

  // 安全统计状态
  const securityStats = ref({})
  const statsLoading = ref(false)

  // 最近安全事件状态
  const recentSecurityEvents = ref([])
  const eventsLoading = ref(false)

  // 计算属性
  const securityOverview = computed(() => {
    return {
      totalIps: ipWhitelistTotal.value,
      activeIps: ipWhitelist.value.filter(ip => ip.status === 'active').length,
      inactiveIps: ipWhitelist.value.filter(ip => ip.status === 'inactive').length,
      activeSessions: sessionsTotal.value,
      securityLevel: securityConfig.value.security_level || 'medium'
    }
  })

  const policyCompliance = computed(() => {
    const policy = passwordPolicy.value
    let score = 0
    let total = 0

    if (policy) {
      if (policy.min_length >= 8) score++
      total++

      if (policy.require_uppercase) score++
      total++

      if (policy.require_lowercase) score++
      total++

      if (policy.require_numbers) score++
      total++

      if (policy.require_special_chars) score++
      total++

      if (policy.max_age_days <= 90) score++
      total++
    }

    return {
      score,
      total,
      percentage: total > 0 ? Math.round((score / total) * 100) : 0
    }
  })

  // 安全配置操作
  const loadSecurityConfig = async () => {
    try {
      securityConfigLoading.value = true
      const response = await authAdminApi.securityConfig.getSecurityConfig()
      securityConfig.value = response.data || {}
      return response
    } catch (error) {
      console.error('加载安全配置失败:', error)
      throw error
    } finally {
      securityConfigLoading.value = false
    }
  }

  const updateSecurityConfig = async (configData) => {
    try {
      securityConfigLoading.value = true
      const response = await authAdminApi.securityConfig.updateSecurityConfig(configData)
      securityConfig.value = { ...securityConfig.value, ...configData }
      return response
    } catch (error) {
      console.error('更新安全配置失败:', error)
      throw error
    } finally {
      securityConfigLoading.value = false
    }
  }

  // IP白名单操作
  const loadIpWhitelist = async (params = {}) => {
    try {
      ipWhitelistLoading.value = true
      const response = await authAdminApi.ipWhitelist.getIpWhitelist({
        page: ipWhitelistPage.value,
        size: ipWhitelistPageSize.value,
        ...params
      })
      ipWhitelist.value = response.data || []
      ipWhitelistTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载IP白名单失败:', error)
      throw error
    } finally {
      ipWhitelistLoading.value = false
    }
  }

  const addIpAddress = async (ipData) => {
    try {
      const response = await authAdminApi.ipWhitelist.addIpAddress(ipData)
      await loadIpWhitelist()
      return response
    } catch (error) {
      console.error('添加IP地址失败:', error)
      throw error
    }
  }

  const updateIpAddress = async (ipId, ipData) => {
    try {
      const response = await authAdminApi.ipWhitelist.updateIpAddress(ipId, ipData)
      await loadIpWhitelist()
      return response
    } catch (error) {
      console.error('更新IP地址失败:', error)
      throw error
    }
  }

  const deleteIpAddress = async (ipId) => {
    try {
      const response = await authAdminApi.ipWhitelist.deleteIpAddress(ipId)
      await loadIpWhitelist()
      return response
    } catch (error) {
      console.error('删除IP地址失败:', error)
      throw error
    }
  }

  const enableIpAddress = async (ipId) => {
    try {
      const response = await authAdminApi.ipWhitelist.enableIpAddress(ipId)
      await loadIpWhitelist()
      return response
    } catch (error) {
      console.error('启用IP地址失败:', error)
      throw error
    }
  }

  const disableIpAddress = async (ipId) => {
    try {
      const response = await authAdminApi.ipWhitelist.disableIpAddress(ipId)
      await loadIpWhitelist()
      return response
    } catch (error) {
      console.error('禁用IP地址失败:', error)
      throw error
    }
  }

  const batchToggleIpAddresses = async (ipIds, enabled) => {
    try {
      const response = await authAdminApi.ipWhitelist.batchToggleIpAddresses(ipIds, enabled)
      await loadIpWhitelist()
      return response
    } catch (error) {
      console.error('批量操作IP地址失败:', error)
      throw error
    }
  }

  // 密码策略操作
  const loadPasswordPolicy = async () => {
    try {
      passwordPolicyLoading.value = true
      const response = await authAdminApi.passwordPolicy.getPasswordPolicy()
      passwordPolicy.value = response.data || {}
      return response
    } catch (error) {
      console.error('加载密码策略失败:', error)
      throw error
    } finally {
      passwordPolicyLoading.value = false
    }
  }

  const updatePasswordPolicy = async (policyData) => {
    try {
      passwordPolicyLoading.value = true
      const response = await authAdminApi.passwordPolicy.updatePasswordPolicy(policyData)
      passwordPolicy.value = { ...passwordPolicy.value, ...policyData }
      return response
    } catch (error) {
      console.error('更新密码策略失败:', error)
      throw error
    } finally {
      passwordPolicyLoading.value = false
    }
  }

  const testPasswordComplexity = async (password) => {
    try {
      const response = await authAdminApi.passwordPolicy.testPasswordComplexity(password)
      return response
    } catch (error) {
      console.error('测试密码复杂度失败:', error)
      throw error
    }
  }

  const resetPasswordPolicy = async () => {
    try {
      passwordPolicyLoading.value = true
      const response = await authAdminApi.passwordPolicy.resetToDefaults()
      await loadPasswordPolicy()
      return response
    } catch (error) {
      console.error('重置密码策略失败:', error)
      throw error
    } finally {
      passwordPolicyLoading.value = false
    }
  }

  // 会话管理操作
  const loadActiveSessions = async (params = {}) => {
    try {
      sessionsLoading.value = true
      const response = await authAdminApi.session.getActiveSessions({
        page: sessionsPage.value,
        size: sessionsPageSize.value,
        ...params
      })
      activeSessions.value = response.data || []
      sessionsTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载活跃会话失败:', error)
      throw error
    } finally {
      sessionsLoading.value = false
    }
  }

  const terminateSession = async (sessionId) => {
    try {
      const response = await authAdminApi.session.terminateSession(sessionId)
      await loadActiveSessions()
      return response
    } catch (error) {
      console.error('结束会话失败:', error)
      throw error
    }
  }

  const batchTerminateSessions = async (sessionIds) => {
    try {
      const response = await authAdminApi.session.batchTerminateSessions(sessionIds)
      await loadActiveSessions()
      return response
    } catch (error) {
      console.error('批量结束会话失败:', error)
      throw error
    }
  }

  // 安全统计操作
  const loadSecurityStats = async () => {
    try {
      statsLoading.value = true
      const response = await authAdminApi.securityConfig.getSecurityStats()
      securityStats.value = response.data || {}
      return response
    } catch (error) {
      console.error('加载安全统计失败:', error)
      throw error
    } finally {
      statsLoading.value = false
    }
  }

  const loadRecentSecurityEvents = async (limit = 10) => {
    try {
      eventsLoading.value = true
      const response = await authAdminApi.securityConfig.getRecentSecurityEvents(limit)
      recentSecurityEvents.value = response.data || []
      return response
    } catch (error) {
      console.error('加载最近安全事件失败:', error)
      throw error
    } finally {
      eventsLoading.value = false
    }
  }

  // 重置状态
  const reset = () => {
    securityConfig.value = {}
    securityConfigLoading.value = false

    ipWhitelist.value = []
    ipWhitelistLoading.value = false
    ipWhitelistTotal.value = 0
    ipWhitelistPage.value = 1
    ipWhitelistPageSize.value = 10

    passwordPolicy.value = {}
    passwordPolicyLoading.value = false

    activeSessions.value = []
    sessionsLoading.value = false
    sessionsTotal.value = 0
    sessionsPage.value = 1
    sessionsPageSize.value = 10

    securityStats.value = {}
    statsLoading.value = false

    recentSecurityEvents.value = []
    eventsLoading.value = false
  }

  return {
    // 状态
    securityConfig,
    securityConfigLoading,

    ipWhitelist,
    ipWhitelistLoading,
    ipWhitelistTotal,
    ipWhitelistPage,
    ipWhitelistPageSize,

    passwordPolicy,
    passwordPolicyLoading,

    activeSessions,
    sessionsLoading,
    sessionsTotal,
    sessionsPage,
    sessionsPageSize,

    securityStats,
    statsLoading,

    recentSecurityEvents,
    eventsLoading,

    // 计算属性
    securityOverview,
    policyCompliance,

    // 操作
    loadSecurityConfig,
    updateSecurityConfig,

    loadIpWhitelist,
    addIpAddress,
    updateIpAddress,
    deleteIpAddress,
    enableIpAddress,
    disableIpAddress,
    batchToggleIpAddresses,

    loadPasswordPolicy,
    updatePasswordPolicy,
    testPasswordComplexity,
    resetPasswordPolicy,

    loadActiveSessions,
    terminateSession,
    batchTerminateSessions,

    loadSecurityStats,
    loadRecentSecurityEvents,

    reset
  }
})