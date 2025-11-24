import api from './index'

export const authApi = {
  login: (credentials) => api.post('/auth/login', credentials),
  checkPasswordExpiry: () => api.get('/auth/check-password-expiry'),
  changePassword: (data) => api.post('/auth/change-password', data),
  logout: () => api.post('/auth/logout'),
  getCurrentUser: () => api.get('/auth/me')
}