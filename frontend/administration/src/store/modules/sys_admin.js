import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import sysAdminApi from '@/api/sys_admin'

export const useSysAdminStore = defineStore('sys_admin', () => {
  // 用户管理状态
  const users = ref([])
  const usersLoading = ref(false)
  const usersTotal = ref(0)
  const usersPage = ref(1)
  const usersPageSize = ref(10)

  // 模型管理状态
  const models = ref([])
  const modelsLoading = ref(false)
  const modelsTotal = ref(0)
  const modelsPage = ref(1)
  const modelsPageSize = ref(10)

  // 用户组管理状态
  const groups = ref([])
  const groupsLoading = ref(false)
  const groupsTotal = ref(0)
  const groupsPage = ref(1)
  const groupsPageSize = ref(10)

  // API密钥管理状态
  const apiKeys = ref([])
  const apiKeysLoading = ref(false)
  const apiKeysTotal = ref(0)
  const apiKeysPage = ref(1)
  const apiKeysPageSize = ref(10)

  // 统计信息状态
  const systemStats = ref({})
  const statsLoading = ref(false)

  // 计算属性
  const userStats = computed(() => {
    return {
      total: usersTotal.value,
      active: users.value.filter(user => user.status === 'active').length,
      inactive: users.value.filter(user => user.status === 'inactive').length
    }
  })

  const modelStats = computed(() => {
    return {
      total: modelsTotal.value,
      enabled: models.value.filter(model => model.enabled).length,
      disabled: models.value.filter(model => !model.enabled).length
    }
  })

  const groupStats = computed(() => {
    return {
      total: groupsTotal.value,
      users: groups.value.reduce((total, group) => total + (group.user_count || 0), 0)
    }
  })

  // 用户管理操作
  const loadUsers = async (apiKey, params = {}) => {
    try {
      usersLoading.value = true
      const response = await sysAdminApi.user.getUsers(apiKey, {
        page: usersPage.value,
        size: usersPageSize.value,
        ...params
      })
      users.value = response.data || []
      usersTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载用户列表失败:', error)
      throw error
    } finally {
      usersLoading.value = false
    }
  }

  const createUser = async (apiKey, userData) => {
    try {
      const response = await sysAdminApi.user.createUser(apiKey, userData)
      await loadUsers(apiKey)
      return response
    } catch (error) {
      console.error('创建用户失败:', error)
      throw error
    }
  }

  const updateUser = async (apiKey, userId, userData) => {
    try {
      const response = await sysAdminApi.user.updateUser(apiKey, userId, userData)
      await loadUsers(apiKey)
      return response
    } catch (error) {
      console.error('更新用户失败:', error)
      throw error
    }
  }

  const deleteUser = async (apiKey, userId) => {
    try {
      const response = await sysAdminApi.user.deleteUser(apiKey, userId)
      await loadUsers(apiKey)
      return response
    } catch (error) {
      console.error('删除用户失败:', error)
      throw error
    }
  }

  // 模型管理操作
  const loadModels = async (apiKey, params = {}) => {
    try {
      modelsLoading.value = true
      const response = await sysAdminApi.model.getModels(apiKey, {
        page: modelsPage.value,
        size: modelsPageSize.value,
        ...params
      })
      models.value = response.data || []
      modelsTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载模型列表失败:', error)
      throw error
    } finally {
      modelsLoading.value = false
    }
  }

  const addModel = async (apiKey, modelData) => {
    try {
      const response = await sysAdminApi.model.addModel(apiKey, modelData)
      await loadModels(apiKey)
      return response
    } catch (error) {
      console.error('添加模型失败:', error)
      throw error
    }
  }

  const updateModel = async (apiKey, modelId, modelData) => {
    try {
      const response = await sysAdminApi.model.updateModel(apiKey, modelId, modelData)
      await loadModels(apiKey)
      return response
    } catch (error) {
      console.error('更新模型失败:', error)
      throw error
    }
  }

  const deleteModel = async (apiKey, modelId) => {
    try {
      const response = await sysAdminApi.model.deleteModel(apiKey, modelId)
      await loadModels(apiKey)
      return response
    } catch (error) {
      console.error('删除模型失败:', error)
      throw error
    }
  }

  // 用户组管理操作
  const loadGroups = async (apiKey, params = {}) => {
    try {
      groupsLoading.value = true
      const response = await sysAdminApi.group.getGroups(apiKey, {
        page: groupsPage.value,
        size: groupsPageSize.value,
        ...params
      })
      groups.value = response.data || []
      groupsTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载用户组列表失败:', error)
      throw error
    } finally {
      groupsLoading.value = false
    }
  }

  const createGroup = async (apiKey, groupData) => {
    try {
      const response = await sysAdminApi.group.createGroup(apiKey, groupData)
      await loadGroups(apiKey)
      return response
    } catch (error) {
      console.error('创建用户组失败:', error)
      throw error
    }
  }

  const updateGroup = async (apiKey, groupId, groupData) => {
    try {
      const response = await sysAdminApi.group.updateGroup(apiKey, groupId, groupData)
      await loadGroups(apiKey)
      return response
    } catch (error) {
      console.error('更新用户组失败:', error)
      throw error
    }
  }

  const deleteGroup = async (apiKey, groupId) => {
    try {
      const response = await sysAdminApi.group.deleteGroup(apiKey, groupId)
      await loadGroups(apiKey)
      return response
    } catch (error) {
      console.error('删除用户组失败:', error)
      throw error
    }
  }

  // API密钥管理操作
  const loadApiKeys = async (params = {}) => {
    try {
      apiKeysLoading.value = true
      const response = await sysAdminApi.apiKey.getApiKeys({
        page: apiKeysPage.value,
        size: apiKeysPageSize.value,
        ...params
      })
      apiKeys.value = response.data || []
      apiKeysTotal.value = response.total || 0
      return response
    } catch (error) {
      console.error('加载API密钥列表失败:', error)
      throw error
    } finally {
      apiKeysLoading.value = false
    }
  }

  const createApiKey = async (apiKeyData) => {
    try {
      const response = await sysAdminApi.apiKey.createApiKey(apiKeyData)
      await loadApiKeys()
      return response
    } catch (error) {
      console.error('创建API密钥失败:', error)
      throw error
    }
  }

  const deleteApiKey = async (keyId) => {
    try {
      const response = await sysAdminApi.apiKey.deleteApiKey(keyId)
      await loadApiKeys()
      return response
    } catch (error) {
      console.error('删除API密钥失败:', error)
      throw error
    }
  }

  const enableApiKey = async (keyId) => {
    try {
      const response = await sysAdminApi.apiKey.enableApiKey(keyId)
      await loadApiKeys()
      return response
    } catch (error) {
      console.error('启用API密钥失败:', error)
      throw error
    }
  }

  const disableApiKey = async (keyId) => {
    try {
      const response = await sysAdminApi.apiKey.disableApiKey(keyId)
      await loadApiKeys()
      return response
    } catch (error) {
      console.error('禁用API密钥失败:', error)
      throw error
    }
  }

  // 统计信息操作
  const loadSystemStats = async () => {
    try {
      statsLoading.value = true
      const response = await sysAdminApi.stats.getSystemStats()
      systemStats.value = response.data || {}
      return response
    } catch (error) {
      console.error('加载系统统计信息失败:', error)
      throw error
    } finally {
      statsLoading.value = false
    }
  }

  // 重置状态
  const reset = () => {
    users.value = []
    usersLoading.value = false
    usersTotal.value = 0
    usersPage.value = 1
    usersPageSize.value = 10

    models.value = []
    modelsLoading.value = false
    modelsTotal.value = 0
    modelsPage.value = 1
    modelsPageSize.value = 10

    groups.value = []
    groupsLoading.value = false
    groupsTotal.value = 0
    groupsPage.value = 1
    groupsPageSize.value = 10

    apiKeys.value = []
    apiKeysLoading.value = false
    apiKeysTotal.value = 0
    apiKeysPage.value = 1
    apiKeysPageSize.value = 10

    systemStats.value = {}
    statsLoading.value = false
  }

  return {
    // 状态
    users,
    usersLoading,
    usersTotal,
    usersPage,
    usersPageSize,

    models,
    modelsLoading,
    modelsTotal,
    modelsPage,
    modelsPageSize,

    groups,
    groupsLoading,
    groupsTotal,
    groupsPage,
    groupsPageSize,

    apiKeys,
    apiKeysLoading,
    apiKeysTotal,
    apiKeysPage,
    apiKeysPageSize,

    systemStats,
    statsLoading,

    // 计算属性
    userStats,
    modelStats,
    groupStats,

    // 操作
    loadUsers,
    createUser,
    updateUser,
    deleteUser,

    loadModels,
    addModel,
    updateModel,
    deleteModel,

    loadGroups,
    createGroup,
    updateGroup,
    deleteGroup,

    loadApiKeys,
    createApiKey,
    deleteApiKey,
    enableApiKey,
    disableApiKey,

    loadSystemStats,

    reset
  }
})