import { defineStore } from 'pinia'
import { authApi } from '@/api/auth'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    token: localStorage.getItem('admin_token') || null,
    isAuthenticated: false
  }),

  getters: {
    userRole: (state) => state.user?.role,
    userName: (state) => state.user?.username,
    displayName: (state) => state.user?.display_name
  },

  actions: {
    async login(credentials) {
      try {
        const response = await authApi.login(credentials)

        if (response.success) {
          this.token = response.access_token
          this.user = response.user
          this.isAuthenticated = true

          // 保存token到localStorage
          localStorage.setItem('admin_token', response.access_token)

          return { success: true }
        } else {
          return {
            success: false,
            error: response.error,
            message: response.message
          }
        }
      } catch (error) {
        console.error('登录失败:', error)
        return {
          success: false,
          error: 'network_error',
          message: '网络错误，请稍后重试'
        }
      }
    },

    async logout() {
      try {
        await authApi.logout()
      } catch (error) {
        console.error('登出失败:', error)
      } finally {
        this.token = null
        this.user = null
        this.isAuthenticated = false
        localStorage.removeItem('admin_token')
      }
    },

    async checkAuth() {
      if (!this.token) {
        this.isAuthenticated = false
        return false
      }

      try {
        const userInfo = await authApi.getCurrentUser()
        this.user = userInfo
        this.isAuthenticated = true
        return true
      } catch (error) {
        console.error('验证登录状态失败:', error)
        this.logout()
        return false
      }
    },

    async changePassword(data) {
      try {
        const response = await authApi.changePassword(data)
        return { success: true, message: response.message }
      } catch (error) {
        console.error('修改密码失败:', error)
        return {
          success: false,
          message: error.response?.data?.detail || '修改密码失败'
        }
      }
    }
  }
})