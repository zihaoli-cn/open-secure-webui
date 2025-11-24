/**
 * 共享工具函数
 * 为三员管理系统提供通用的工具函数
 */

/**
 * 格式化日期时间
 * @param {string|Date} date - 日期时间
 * @param {string} format - 格式类型: 'datetime' | 'date' | 'time'
 * @returns {string} 格式化后的字符串
 */
export const formatDateTime = (date, format = 'datetime') => {
  if (!date) return ''

  const d = new Date(date)

  switch (format) {
    case 'date':
      return d.toLocaleDateString('zh-CN')
    case 'time':
      return d.toLocaleTimeString('zh-CN')
    case 'datetime':
    default:
      return d.toLocaleString('zh-CN')
  }
}

/**
 * 格式化文件大小
 * @param {number} bytes - 字节数
 * @returns {string} 格式化后的文件大小
 */
export const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 B'

  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

/**
 * 防抖函数
 * @param {Function} func - 要防抖的函数
 * @param {number} wait - 等待时间(毫秒)
 * @returns {Function} 防抖后的函数
 */
export const debounce = (func, wait) => {
  let timeout
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }
    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }
}

/**
 * 节流函数
 * @param {Function} func - 要节流的函数
 * @param {number} limit - 限制时间(毫秒)
 * @returns {Function} 节流后的函数
 */
export const throttle = (func, limit) => {
  let inThrottle
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}

/**
 * 深度克隆对象
 * @param {any} obj - 要克隆的对象
 * @returns {any} 克隆后的对象
 */
export const deepClone = (obj) => {
  if (obj === null || typeof obj !== 'object') return obj
  if (obj instanceof Date) return new Date(obj.getTime())
  if (obj instanceof Array) return obj.map(item => deepClone(item))
  if (obj instanceof Object) {
    const clonedObj = {}
    Object.keys(obj).forEach(key => {
      clonedObj[key] = deepClone(obj[key])
    })
    return clonedObj
  }
}

/**
 * 生成随机ID
 * @param {number} length - ID长度
 * @returns {string} 随机ID
 */
export const generateId = (length = 8) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

/**
 * 验证邮箱格式
 * @param {string} email - 邮箱地址
 * @returns {boolean} 是否有效
 */
export const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

/**
 * 验证IP地址格式
 * @param {string} ip - IP地址
 * @returns {boolean} 是否有效
 */
export const validateIP = (ip) => {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
  if (!ipRegex.test(ip)) return false

  const parts = ip.split('.')
  return parts.every(part => {
    const num = parseInt(part, 10)
    return num >= 0 && num <= 255
  })
}

/**
 * 验证URL格式
 * @param {string} url - URL地址
 * @returns {boolean} 是否有效
 */
export const validateURL = (url) => {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

/**
 * 获取操作类型标签配置
 * @param {string} type - 操作类型
 * @returns {Object} 标签配置 {type: string, label: string}
 */
export const getOperationTypeConfig = (type) => {
  const configMap = {
    'login': { type: 'primary', label: '登录' },
    'logout': { type: 'info', label: '登出' },
    'create': { type: 'success', label: '创建' },
    'update': { type: 'warning', label: '更新' },
    'delete': { type: 'danger', label: '删除' },
    'read': { type: '', label: '读取' }
  }
  return configMap[type] || { type: 'info', label: type }
}

/**
 * 获取严重程度标签配置
 * @param {string} severity - 严重程度
 * @returns {Object} 标签配置 {type: string, label: string}
 */
export const getSeverityConfig = (severity) => {
  const configMap = {
    'critical': { type: 'danger', label: '严重' },
    'warning': { type: 'warning', label: '警告' },
    'info': { type: 'info', label: '信息' }
  }
  return configMap[severity] || { type: 'info', label: severity }
}

/**
 * 格式化JSON字符串
 * @param {string|Object} data - JSON数据
 * @returns {string} 格式化后的字符串
 */
export const formatJSON = (data) => {
  if (typeof data === 'string') {
    try {
      return JSON.stringify(JSON.parse(data), null, 2)
    } catch {
      return data
    }
  } else if (typeof data === 'object') {
    return JSON.stringify(data, null, 2)
  }
  return String(data)
}

/**
 * 下载文件
 * @param {string} content - 文件内容
 * @param {string} filename - 文件名
 * @param {string} contentType - 文件类型
 */
export const downloadFile = (content, filename, contentType = 'text/plain') => {
  const blob = new Blob([content], { type: contentType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/**
 * 获取角色显示名称
 * @param {string} role - 角色标识
 * @returns {string} 显示名称
 */
export const getRoleDisplayName = (role) => {
  const roleMap = {
    'sys_admin': '系统管理员',
    'auth_admin': '安全管理员',
    'audit_admin': '审计管理员',
    'user': '普通用户'
  }
  return roleMap[role] || role
}

/**
 * 获取状态显示名称
 * @param {string} status - 状态标识
 * @returns {string} 显示名称
 */
export const getStatusDisplayName = (status) => {
  const statusMap = {
    'active': '激活',
    'inactive': '未激活',
    'pending': '待审核',
    'success': '成功',
    'failed': '失败',
    'online': '在线',
    'offline': '离线'
  }
  return statusMap[status] || status
}

/**
 * 检查权限
 * @param {string} userRole - 用户角色
 * @param {string} requiredRole - 所需角色
 * @returns {boolean} 是否有权限
 */
export const hasPermission = (userRole, requiredRole) => {
  const roleHierarchy = {
    'sys_admin': ['sys_admin', 'auth_admin', 'audit_admin', 'user'],
    'auth_admin': ['auth_admin', 'audit_admin', 'user'],
    'audit_admin': ['audit_admin', 'user'],
    'user': ['user']
  }

  return roleHierarchy[userRole]?.includes(requiredRole) || false
}