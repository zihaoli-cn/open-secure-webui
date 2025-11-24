<template>
  <div class="sys-admin-dashboard">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1 class="page-title">系统管理</h1>
      <p class="page-description">管理系统用户、模型、用户组和API密钥</p>
    </div>

    <!-- 统计卡片 -->
    <el-row :gutter="20" class="stats-cards">
      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon user-icon">
              <el-icon><User /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ userStats.total || 0 }}</div>
              <div class="stat-label">用户总数</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="active-users">活跃: {{ userStats.active || 0 }}</span>
            <span class="inactive-users">非活跃: {{ userStats.inactive || 0 }}</span>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon model-icon">
              <el-icon><Cpu /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ modelStats.total || 0 }}</div>
              <div class="stat-label">模型总数</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="enabled-models">启用: {{ modelStats.enabled || 0 }}</span>
            <span class="disabled-models">禁用: {{ modelStats.disabled || 0 }}</span>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon group-icon">
              <el-icon><UserFilled /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ groupStats.total || 0 }}</div>
              <div class="stat-label">用户组数</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="total-users">总用户数: {{ groupStats.users || 0 }}</span>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon key-icon">
              <el-icon><Key /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ apiKeysTotal || 0 }}</div>
              <div class="stat-label">API密钥</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="active-keys">活跃: {{ activeApiKeysCount }}</span>
            <span class="expired-keys">过期: {{ expiredApiKeysCount }}</span>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 快速操作 -->
    <el-card class="quick-actions-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span class="card-title">快速操作</span>
        </div>
      </template>
      <el-row :gutter="20">
        <el-col :span="6">
          <el-button
            type="primary"
            class="action-button"
            @click="$router.push('/sys-admin/users')"
          >
            <el-icon><User /></el-icon>
            用户管理
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button
            type="success"
            class="action-button"
            @click="$router.push('/sys-admin/models')"
          >
            <el-icon><Cpu /></el-icon>
            模型管理
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button
            type="warning"
            class="action-button"
            @click="$router.push('/sys-admin/groups')"
          >
            <el-icon><UserFilled /></el-icon>
            用户组管理
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button
            type="info"
            class="action-button"
            @click="$router.push('/sys-admin/api-keys')"
          >
            <el-icon><Key /></el-icon>
            API密钥管理
          </el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- 最近活动 -->
    <el-row :gutter="20" class="activity-section">
      <el-col :span="12">
        <el-card class="activity-card" shadow="never">
          <template #header>
            <div class="card-header">
              <span class="card-title">最近用户活动</span>
            </div>
          </template>
          <div class="activity-list" v-loading="usersLoading">
            <div
              v-for="user in recentUsers"
              :key="user.id"
              class="activity-item"
            >
              <div class="activity-avatar">
                <el-avatar :size="32" :src="user.avatar">
                  {{ user.username?.charAt(0).toUpperCase() }}
                </el-avatar>
              </div>
              <div class="activity-content">
                <div class="activity-title">
                  <span class="username">{{ user.username }}</span>
                  <span class="activity-time">{{ formatTime(user.last_login) }}</span>
                </div>
                <div class="activity-desc">
                  最后登录: {{ user.last_login ? '已登录' : '未登录' }}
                </div>
              </div>
            </div>
            <div v-if="recentUsers.length === 0" class="empty-activity">
              暂无用户活动
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card class="activity-card" shadow="never">
          <template #header>
            <div class="card-header">
              <span class="card-title">最近API使用</span>
            </div>
          </template>
          <div class="activity-list" v-loading="apiKeysLoading">
            <div
              v-for="key in recentApiKeys"
              :key="key.id"
              class="activity-item"
            >
              <div class="activity-avatar">
                <el-avatar :size="32" icon="Key" />
              </div>
              <div class="activity-content">
                <div class="activity-title">
                  <span class="key-name">{{ key.name }}</span>
                  <el-tag
                    :type="getStatusType(key.status)"
                    size="small"
                  >
                    {{ getStatusText(key.status) }}
                  </el-tag>
                </div>
                <div class="activity-desc">
                  用户: {{ key.username }} | 创建: {{ formatTime(key.created_at) }}
                </div>
              </div>
            </div>
            <div v-if="recentApiKeys.length === 0" class="empty-activity">
              暂无API使用记录
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useSysAdminStore } from '@/store/modules/sys_admin'
import { User, Cpu, UserFilled, Key } from '@element-plus/icons-vue'

const router = useRouter()
const sysAdminStore = useSysAdminStore()

// 计算属性
const activeApiKeysCount = computed(() => {
  return sysAdminStore.apiKeys.filter(key => key.status === 'active').length
})

const expiredApiKeysCount = computed(() => {
  return sysAdminStore.apiKeys.filter(key => key.status === 'expired').length
})

const recentUsers = computed(() => {
  return sysAdminStore.users
    .sort((a, b) => new Date(b.last_login || 0) - new Date(a.last_login || 0))
    .slice(0, 5)
})

const recentApiKeys = computed(() => {
  return sysAdminStore.apiKeys
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5)
})

// 状态类型映射
const getStatusType = (status) => {
  const typeMap = {
    'active': 'success',
    'disabled': 'warning',
    'expired': 'danger'
  }
  return typeMap[status] || 'info'
}

const getStatusText = (status) => {
  const textMap = {
    'active': '活跃',
    'disabled': '已禁用',
    'expired': '已过期'
  }
  return textMap[status] || '未知'
}

// 格式化时间
const formatTime = (time) => {
  if (!time) return '--'
  const date = new Date(time)
  const now = new Date()
  const diff = now - date

  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}分钟前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}小时前`
  if (diff < 604800000) return `${Math.floor(diff / 86400000)}天前`

  return date.toLocaleDateString('zh-CN')
}

// 初始化数据
const initData = async () => {
  try {
    await Promise.all([
      sysAdminStore.loadUsers({ size: 10 }),
      sysAdminStore.loadModels({ size: 10 }),
      sysAdminStore.loadGroups({ size: 10 }),
      sysAdminStore.loadApiKeys({ size: 10 }),
      sysAdminStore.loadSystemStats()
    ])
  } catch (error) {
    console.error('初始化数据失败:', error)
  }
}

onMounted(() => {
  initData()
})
</script>

<style scoped>
.sys-admin-dashboard {
  padding: 20px;
}

.page-header {
  margin-bottom: 24px;
}

.page-title {
  font-size: 24px;
  font-weight: 600;
  color: #303133;
  margin: 0 0 8px 0;
}

.page-description {
  color: #909399;
  font-size: 14px;
  margin: 0;
}

.stats-cards {
  margin-bottom: 24px;
}

.stat-card {
  border-radius: 8px;
  border: none;
}

.stat-content {
  display: flex;
  align-items: center;
  margin-bottom: 12px;
}

.stat-icon {
  width: 48px;
  height: 48px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 16px;
  font-size: 24px;
}

.user-icon {
  background: #e6f7ff;
  color: #1890ff;
}

.model-icon {
  background: #f6ffed;
  color: #52c41a;
}

.group-icon {
  background: #fff7e6;
  color: #fa8c16;
}

.key-icon {
  background: #f9f0ff;
  color: #722ed1;
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 24px;
  font-weight: 600;
  color: #303133;
  line-height: 1;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-top: 4px;
}

.stat-details {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  color: #606266;
}

.active-users,
.enabled-models,
.active-keys {
  color: #52c41a;
}

.inactive-users,
.disabled-models,
.expired-keys {
  color: #f5222d;
}

.quick-actions-card {
  margin-bottom: 24px;
  border-radius: 8px;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.card-title {
  font-size: 16px;
  font-weight: 500;
  color: #303133;
}

.action-button {
  width: 100%;
  height: 80px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  gap: 8px;
}

.activity-section {
  margin-bottom: 20px;
}

.activity-card {
  border-radius: 8px;
}

.activity-list {
  min-height: 200px;
}

.activity-item {
  display: flex;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid #f0f0f0;
}

.activity-item:last-child {
  border-bottom: none;
}

.activity-avatar {
  margin-right: 12px;
}

.activity-content {
  flex: 1;
}

.activity-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 4px;
}

.username,
.key-name {
  font-weight: 500;
  color: #303133;
}

.activity-time {
  font-size: 12px;
  color: #909399;
}

.activity-desc {
  font-size: 12px;
  color: #606266;
}

.empty-activity {
  text-align: center;
  color: #909399;
  padding: 40px 0;
}
</style>