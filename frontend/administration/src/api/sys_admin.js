import api from './index.js'

// 通用代理API
export const proxyApi = {
  // 代理请求到Open WebUI后端
  proxy: (apiKey, method, path, data = null, params = null) => {
    return api.post('/sys-admin/proxy', {
      api_key: apiKey,
      method: method,
      path: path,
      data: data,
      params: params
    })
  }
}

// 用户管理API
export const userApi = {
  // 获取用户列表
  getUsers: (apiKey, params = {}) => {
    return proxyApi.proxy(apiKey, 'GET', '/api/v1/auths/admin/details', null, params)
  },

  // 创建用户
  createUser: (apiKey, userData) => {
    return proxyApi.proxy(apiKey, 'POST', '/api/v1/auths/admin/create', userData)
  },

  // 更新用户
  updateUser: (apiKey, userId, userData) => {
    return proxyApi.proxy(apiKey, 'PUT', `/api/v1/auths/admin/${userId}`, userData)
  },

  // 删除用户
  deleteUser: (apiKey, userId) => {
    return proxyApi.proxy(apiKey, 'DELETE', `/api/v1/auths/admin/${userId}`)
  },

  // 重置用户密码
  resetPassword: (apiKey, userId, newPassword) => {
    return proxyApi.proxy(apiKey, 'POST', `/api/v1/auths/admin/${userId}/reset-password`, { new_password: newPassword })
  }
}

// 模型管理API
export const modelApi = {
  // 获取模型列表
  getModels: (apiKey, params = {}) => {
    return proxyApi.proxy(apiKey, 'GET', '/api/v1/models', null, params)
  },

  // 添加模型
  addModel: (apiKey, modelData) => {
    return proxyApi.proxy(apiKey, 'POST', '/api/v1/models', modelData)
  },

  // 更新模型
  updateModel: (apiKey, modelId, modelData) => {
    return proxyApi.proxy(apiKey, 'PUT', `/api/v1/models/${modelId}`, modelData)
  },

  // 删除模型
  deleteModel: (apiKey, modelId) => {
    return proxyApi.proxy(apiKey, 'DELETE', `/api/v1/models/${modelId}`)
  },

  // 启用/禁用模型
  toggleModel: (apiKey, modelId, enabled) => {
    return proxyApi.proxy(apiKey, 'PATCH', `/api/v1/models/${modelId}/toggle`, { enabled })
  }
}

// 用户组管理API
export const groupApi = {
  // 获取用户组列表
  getGroups: (apiKey, params = {}) => {
    return proxyApi.proxy(apiKey, 'GET', '/api/v1/groups', null, params)
  },

  // 创建用户组
  createGroup: (apiKey, groupData) => {
    return proxyApi.proxy(apiKey, 'POST', '/api/v1/groups', groupData)
  },

  // 更新用户组
  updateGroup: (apiKey, groupId, groupData) => {
    return proxyApi.proxy(apiKey, 'PUT', `/api/v1/groups/${groupId}`, groupData)
  },

  // 删除用户组
  deleteGroup: (apiKey, groupId) => {
    return proxyApi.proxy(apiKey, 'DELETE', `/api/v1/groups/${groupId}`)
  },

  // 添加用户到组
  addUserToGroup: (apiKey, groupId, userId) => {
    return proxyApi.proxy(apiKey, 'POST', `/api/v1/groups/${groupId}/users`, { user_id: userId })
  },

  // 从组中移除用户
  removeUserFromGroup: (apiKey, groupId, userId) => {
    return proxyApi.proxy(apiKey, 'DELETE', `/api/v1/groups/${groupId}/users/${userId}`)
  },

  // 获取组内用户列表
  getGroupUsers: (apiKey, groupId) => {
    return proxyApi.proxy(apiKey, 'GET', `/api/v1/groups/${groupId}/users`)
  }
}

// API密钥管理API
export const apiKeyApi = {
  // 获取API密钥列表
  getApiKeys: (params = {}) => {
    return api.get('/sys-admin/api-keys', { params })
  },

  // 创建API密钥
  createApiKey: (apiKeyData) => {
    return api.post('/sys-admin/api-keys', apiKeyData)
  },

  // 删除API密钥
  deleteApiKey: (keyId) => {
    return api.delete(`/sys-admin/api-keys/${keyId}`)
  },

  // 启用API密钥
  enableApiKey: (keyId) => {
    return api.patch(`/sys-admin/api-keys/${keyId}/enable`)
  },

  // 禁用API密钥
  disableApiKey: (keyId) => {
    return api.patch(`/sys-admin/api-keys/${keyId}/disable`)
  },

  // 验证API密钥
  validateApiKey: (apiKey) => {
    return api.post('/sys-admin/api-keys/validate', { api_key: apiKey })
  }
}

// 系统统计API
export const statsApi = {
  // 获取系统统计信息
  getSystemStats: () => {
    return api.get('/sys-admin/stats')
  },

  // 获取用户统计
  getUserStats: () => {
    return api.get('/sys-admin/stats/users')
  },

  // 获取模型使用统计
  getModelStats: () => {
    return api.get('/sys-admin/stats/models')
  },

  // 获取API使用统计
  getApiUsageStats: () => {
    return api.get('/sys-admin/stats/api-usage')
  }
}

export default {
  user: userApi,
  model: modelApi,
  group: groupApi,
  apiKey: apiKeyApi,
  stats: statsApi
}