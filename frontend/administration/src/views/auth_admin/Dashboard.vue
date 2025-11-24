<template>
  <div class="auth-admin-dashboard">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1 class="page-title">安全管理</h1>
      <p class="page-description">管理系统安全配置、IP白名单和密码策略</p>
    </div>

    <!-- 统计卡片 -->
    <el-row :gutter="20" class="stats-cards">
      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon security-icon">
              <el-icon><Lock /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ securityOverview.totalIps || 0 }}</div>
              <div class="stat-label">IP白名单</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="active-ips">活跃: {{ securityOverview.activeIps || 0 }}</span>
            <span class="inactive-ips">非活跃: {{ securityOverview.inactiveIps || 0 }}</span>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon session-icon">
              <el-icon><Connection /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ securityOverview.activeSessions || 0 }}</div>
              <div class="stat-label">活跃会话</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="security-level">安全等级: {{ getSecurityLevelText(securityOverview.securityLevel) }}</span>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon policy-icon">
              <el-icon><Document /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ policyCompliance.percentage || 0 }}%</div>
              <div class="stat-label">策略合规率</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="compliance-score">得分: {{ policyCompliance.score || 0 }}/{{ policyCompliance.total || 0 }}</span>
          </div>
        </el-card>
      </el-col>

      <el-col :span="6">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon event-icon">
              <el-icon><Warning /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ recentSecurityEvents.length || 0 }}</div>
              <div class="stat-label">最近事件</div>
            </div>
          </div>
          <div class="stat-details">
            <span class="critical-events">严重: {{ criticalEventsCount }}</span>
            <span class="warning-events">警告: {{ warningEventsCount }}</span>
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
            @click="$router.push('/auth-admin/security-config')"
          >
            <el-icon><Setting /></el-icon>
            安全配置
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button
            type="success"
            class="action-button"
            @click="$router.push('/auth-admin/ip-whitelist')"
          >
            <el-icon><Monitor /></el-icon>
            IP白名单
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button
            type="warning"
            class="action-button"
            @click="$router.push('/auth-admin/password-policy')"
          >
            <el-icon><Lock /></el-icon>
            密码策略
          </el-button>
        </el-col>
        <el-col :span="6">
          <el-button
            type="info"
            class="action-button"
            @click="$router.push('/auth-admin/sessions')"
          >
            <el-icon><Connection /></el-icon>
            会话管理
          </el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- 最近安全事件 -->
    <el-row :gutter="20" class="activity-section">
      <el-col :span="12">
        <el-card class="activity-card" shadow="never">
          <template #header>
            <div class="card-header">
              <span class="card-title">最近安全事件</span>
              <el-button
                type="text"
                size="small"
                @click="loadRecentSecurityEvents"
                :loading="eventsLoading"
              >
                刷新
              </el-button>
            </div>
          </template>
          <div class="activity-list" v-loading="eventsLoading">
            <div
              v-for="event in recentSecurityEvents"
              :key="event.id"
              class="activity-item"
            >
              <div class="activity-avatar">
                <el-avatar :size="32" :style="{ backgroundColor: getEventColor(event.severity) }">
                  <el-icon>
                    <component :is="getEventIcon(event.type)" />
                  </el-icon>
                </el-avatar>
              </div>
              <div class="activity-content">
                <div class="activity-title">
                  <span class="event-title">{{ event.title }}</span>
                  <el-tag
                    :type="getSeverityType(event.severity)"
                    size="small"
                  >
                    {{ getSeverityText(event.severity) }}
                  </el-tag>
                </div>
                <div class="activity-desc">
                  {{ event.description }} | {{ formatTime(event.created_at) }}
                </div>
              </div>
            </div>
            <div v-if="recentSecurityEvents.length === 0" class="empty-activity">
              暂无安全事件
            </div>
          </div>
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card class="activity-card" shadow="never">
          <template #header>
            <div class="card-header">
              <span class="card-title">系统安全状态</span>
            </div>
          </template>
          <div class="security-status" v-loading="statsLoading">
            <div class="status-item">
              <div class="status-label">系统安全等级</div>
              <div class="status-value">
                <el-tag :type="getSecurityLevelType(securityOverview.securityLevel)">
                  {{ getSecurityLevelText(securityOverview.securityLevel) }}
                </el-tag>
              </div>
            </div>
            <div class="status-item">
              <div class="status-label">密码策略合规</div>
              <div class="status-value">
                <el-progress
                  :percentage="policyCompliance.percentage"
                  :status="getComplianceStatus(policyCompliance.percentage)"
                  :stroke-width="8"
                />
              </div>
            </div>
            <div class="status-item">
              <div class="status-label">IP白名单状态</div>
              <div class="status-value">
                <span :class="{ 'text-success': securityOverview.activeIps > 0, 'text-warning': securityOverview.activeIps === 0 }">
                  {{ securityOverview.activeIps > 0 ? '已配置' : '未配置' }}
                </span>
              </div>
            </div>
            <div class="status-item">
              <div class="status-label">会话管理</div>
              <div class="status-value">
                <span :class="{ 'text-info': securityOverview.activeSessions > 0, 'text-muted': securityOverview.activeSessions === 0 }">
                  {{ securityOverview.activeSessions }} 个活跃会话
                </span>
              </div>
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
import { useAuthAdminStore } from '@/store/modules/auth_admin'
import {
  Lock,
  Connection,
  Document,
  Warning,
  Setting,
  Monitor,
  User,
  Key
} from '@element-plus/icons-vue'

const router = useRouter()
const authAdminStore = useAuthAdminStore()

// 计算属性
const criticalEventsCount = computed(() => {
  return authAdminStore.recentSecurityEvents.filter(event => event.severity === 'critical').length
})

const warningEventsCount = computed(() => {
  return authAdminStore.recentSecurityEvents.filter(event => event.severity === 'warning').length
})

// 安全等级文本映射
const getSecurityLevelText = (level) => {
  const levelMap = {
    'low': '低',
    'medium': '中',
    'high': '高',
    'critical': '严格'
  }
  return levelMap[level] || '未知'
}

const getSecurityLevelType = (level) => {
  const typeMap = {
    'low': 'danger',
    'medium': 'warning',
    'high': 'success',
    'critical': 'info'
  }
  return typeMap[level] || 'info'
}

// 事件严重性映射
const getSeverityType = (severity) => {
  const typeMap = {
    'info': 'info',
    'warning': 'warning',
    'critical': 'danger'
  }
  return typeMap[severity] || 'info'
}

const getSeverityText = (severity) => {
  const textMap = {
    'info': '信息',
    'warning': '警告',
    'critical': '严重'
  }
  return textMap[severity] || '未知'
}

const getEventColor = (severity) => {
  const colorMap = {
    'info': '#409EFF',
    'warning': '#E6A23C',
    'critical': '#F56C6C'
  }
  return colorMap[severity] || '#909399'
}

const getEventIcon = (type) => {
  const iconMap = {
    'login': User,
    'password_change': Lock,
    'ip_blocked': Monitor,
    'session_expired': Connection,
    'api_key_created': Key
  }
  return iconMap[type] || Warning
}

// 合规状态
const getComplianceStatus = (percentage) => {
  if (percentage >= 80) return 'success'
  if (percentage >= 60) return 'warning'
  return 'exception'
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

// 加载最近安全事件
const loadRecentSecurityEvents = async () => {
  try {
    await authAdminStore.loadRecentSecurityEvents(10)
  } catch (error) {
    console.error('加载最近安全事件失败:', error)
  }
}

// 初始化数据
const initData = async () => {
  try {
    await Promise.all([
      authAdminStore.loadSecurityConfig(),
      authAdminStore.loadIpWhitelist({ size: 10 }),
      authAdminStore.loadPasswordPolicy(),
      authAdminStore.loadActiveSessions({ size: 10 }),
      authAdminStore.loadSecurityStats(),
      authAdminStore.loadRecentSecurityEvents(10)
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
.auth-admin-dashboard {
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

.security-icon {
  background: #e6f7ff;
  color: #1890ff;
}

.session-icon {
  background: #f6ffed;
  color: #52c41a;
}

.policy-icon {
  background: #fff7e6;
  color: #fa8c16;
}

.event-icon {
  background: #fff2f0;
  color: #ff4d4f;
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

.active-ips,
.compliance-score {
  color: #52c41a;
}

.inactive-ips,
.critical-events {
  color: #f5222d;
}

.warning-events {
  color: #fa8c16;
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

.event-title {
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

.security-status {
  padding: 8px 0;
}

.status-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 0;
  border-bottom: 1px solid #f0f0f0;
}

.status-item:last-child {
  border-bottom: none;
}

.status-label {
  font-size: 14px;
  color: #606266;
}

.status-value {
  font-size: 14px;
  font-weight: 500;
}

.text-success {
  color: #52c41a;
}

.text-warning {
  color: #fa8c16;
}

.text-info {
  color: #1890ff;
}

.text-muted {
  color: #909399;
}
</style>