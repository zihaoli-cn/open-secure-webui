<template>
  <div class="operation-monitor">
    <!-- 页面头部 -->
    <div class="page-header">
      <h1 class="page-title">实时监控</h1>
      <div class="page-actions">
        <el-button
          :type="isMonitoring ? 'danger' : 'success'"
          @click="toggleMonitoring"
        >
          <el-icon v-if="isMonitoring"><VideoPause /></el-icon>
          <el-icon v-else><VideoPlay /></el-icon>
          {{ isMonitoring ? '停止监控' : '开始监控' }}
        </el-button>
        <el-button @click="refreshData">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
      </div>
    </div>

    <!-- 系统状态概览 -->
    <div class="system-status">
      <el-row :gutter="20">
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="status-card">
            <div class="status-content">
              <div class="status-icon system-health">
                <el-icon><Monitor /></el-icon>
              </div>
              <div class="status-info">
                <div class="status-value">{{ systemHealth.status || '未知' }}</div>
                <div class="status-label">系统健康状态</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="status-card">
            <div class="status-content">
              <div class="status-icon active-users">
                <el-icon><User /></el-icon>
              </div>
              <div class="status-info">
                <div class="status-value">{{ activeUsers.length }}</div>
                <div class="status-label">活跃用户</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="status-card">
            <div class="status-content">
              <div class="status-icon operations-rate">
                <el-icon><TrendCharts /></el-icon>
              </div>
              <div class="status-info">
                <div class="status-value">{{ operationsPerMinute }}</div>
                <div class="status-label">操作/分钟</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="status-card">
            <div class="status-content">
              <div class="status-icon anomaly-count">
                <el-icon><Warning /></el-icon>
              </div>
              <div class="status-info">
                <div class="status-value">{{ anomalyAlerts.length }}</div>
                <div class="status-label">异常告警</div>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- 实时操作流 -->
    <div class="realtime-operations">
      <el-card>
        <template #header>
          <div class="section-header">
            <span>实时操作流</span>
            <div class="section-actions">
              <el-button
                type="primary"
                text
                @click="clearOperations"
              >
                清空
              </el-button>
            </div>
          </div>
        </template>

        <div class="operations-container">
          <div
            v-for="operation in realtimeOperations"
            :key="operation.id"
            class="operation-item"
            :class="{ 'critical': operation.severity === 'critical' }"
          >
            <div class="operation-time">
              {{ formatTime(operation.timestamp) }}
            </div>
            <div class="operation-user">
              <el-avatar :size="24" :src="operation.avatar" />
              <span class="username">{{ operation.username }}</span>
            </div>
            <div class="operation-type">
              <el-tag :type="getOperationTypeTag(operation.operation_type)" size="small">
                {{ getOperationTypeLabel(operation.operation_type) }}
              </el-tag>
            </div>
            <div class="operation-description">
              {{ operation.description }}
            </div>
            <div class="operation-status">
              <el-tag
                :type="operation.status === 'success' ? 'success' : 'danger'"
                size="small"
              >
                {{ operation.status === 'success' ? '成功' : '失败' }}
              </el-tag>
            </div>
            <div class="operation-ip">
              {{ operation.ip_address }}
            </div>
          </div>

          <div v-if="realtimeOperations.length === 0" class="empty-operations">
            <el-empty description="暂无实时操作数据" />
          </div>
        </div>
      </el-card>
    </div>

    <!-- 异常告警 -->
    <div class="anomaly-alerts">
      <el-card>
        <template #header>
          <div class="section-header">
            <span>异常告警</span>
            <div class="section-actions">
              <el-button
                type="primary"
                text
                @click="loadAnomalyAlerts"
              >
                刷新
              </el-button>
            </div>
          </div>
        </template>

        <div v-loading="realtimeLoading">
          <el-table :data="anomalyAlerts" style="width: 100%">
            <el-table-column prop="timestamp" label="时间" width="180">
              <template #default="{ row }">
                {{ formatDateTime(row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="username" label="用户" width="120" />
            <el-table-column prop="operation_type" label="操作类型" width="120">
              <template #default="{ row }">
                <el-tag :type="getOperationTypeTag(row.operation_type)">
                  {{ getOperationTypeLabel(row.operation_type) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="操作描述" />
            <el-table-column prop="severity" label="严重程度" width="100">
              <template #default="{ row }">
                <el-tag :type="getSeverityTag(row.severity)">
                  {{ getSeverityLabel(row.severity) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120">
              <template #default="{ row }">
                <el-button
                  type="primary"
                  link
                  @click="viewAlertDetail(row)"
                >
                  详情
                </el-button>
                <el-button
                  type="success"
                  link
                  @click="markAlertAsResolved(row.id)"
                >
                  标记已处理
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-card>
    </div>

    <!-- 活跃用户监控 -->
    <div class="active-users-monitor">
      <el-card>
        <template #header>
          <div class="section-header">
            <span>活跃用户监控</span>
            <div class="section-actions">
              <el-button
                type="primary"
                text
                @click="loadActiveUsersMonitor"
              >
                刷新
              </el-button>
            </div>
          </div>
        </template>

        <div class="users-container">
          <div
            v-for="user in activeUsers"
            :key="user.id"
            class="user-item"
          >
            <div class="user-avatar">
              <el-avatar :size="40" :src="user.avatar" />
            </div>
            <div class="user-info">
              <div class="username">{{ user.username }}</div>
              <div class="user-stats">
                <span class="operation-count">{{ user.operation_count }} 次操作</span>
                <span class="last-active">最后活跃: {{ formatTime(user.last_active) }}</span>
              </div>
            </div>
            <div class="user-status">
              <el-tag :type="user.status === 'online' ? 'success' : 'info'">
                {{ user.status === 'online' ? '在线' : '离线' }}
              </el-tag>
            </div>
          </div>

          <div v-if="activeUsers.length === 0" class="empty-users">
            <el-empty description="暂无活跃用户" />
          </div>
        </div>
      </el-card>
    </div>

    <!-- 告警详情对话框 -->
    <el-dialog
      v-model="alertDetailDialogVisible"
      title="告警详情"
      width="600px"
    >
      <el-descriptions :column="1" border v-if="currentAlert">
        <el-descriptions-item label="ID">
          {{ currentAlert.id }}
        </el-descriptions-item>
        <el-descriptions-item label="时间">
          {{ formatDateTime(currentAlert.timestamp) }}
        </el-descriptions-item>
        <el-descriptions-item label="用户">
          {{ currentAlert.username }}
        </el-descriptions-item>
        <el-descriptions-item label="操作类型">
          <el-tag :type="getOperationTypeTag(currentAlert.operation_type)">
            {{ getOperationTypeLabel(currentAlert.operation_type) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="操作描述">
          {{ currentAlert.description }}
        </el-descriptions-item>
        <el-descriptions-item label="严重程度">
          <el-tag :type="getSeverityTag(currentAlert.severity)">
            {{ getSeverityLabel(currentAlert.severity) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="IP地址">
          {{ currentAlert.ip_address }}
        </el-descriptions-item>
        <el-descriptions-item label="详细信息" v-if="currentAlert.details">
          <pre style="white-space: pre-wrap; font-family: inherit;">{{ formatDetails(currentAlert.details) }}</pre>
        </el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button @click="alertDetailDialogVisible = false">关闭</el-button>
        <el-button
          type="success"
          @click="markCurrentAlertAsResolved"
        >
          标记已处理
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { VideoPlay, VideoPause, Refresh, Monitor, User, TrendCharts, Warning } from '@element-plus/icons-vue'
import { useAuditAdminStore } from '@/store/modules/audit_admin'

const auditAdminStore = useAuditAdminStore()

// 监控状态
const isMonitoring = ref(false)
const operationsPerMinute = ref(0)
const monitoringInterval = ref(null)

// 对话框状态
const alertDetailDialogVisible = ref(false)
const currentAlert = ref(null)

// 计算属性
const realtimeOperations = computed(() => auditAdminStore.realtimeOperations)
const realtimeLoading = computed(() => auditAdminStore.realtimeLoading)
const activeUsers = computed(() => auditAdminStore.activeUsers)
const systemHealth = computed(() => auditAdminStore.systemHealth)
const anomalyAlerts = computed(() => auditAdminStore.anomalyAlerts)

// 初始化数据
const initData = async () => {
  try {
    await Promise.all([
      auditAdminStore.loadRealtimeOperations(),
      auditAdminStore.loadActiveUsersMonitor(),
      auditAdminStore.loadSystemHealthStatus(),
      auditAdminStore.loadAnomalyAlerts()
    ])
  } catch (error) {
    console.error('初始化数据失败:', error)
    ElMessage.error('初始化数据失败')
  }
}

// 刷新数据
const refreshData = async () => {
  await initData()
}

// 切换监控状态
const toggleMonitoring = () => {
  if (isMonitoring.value) {
    stopMonitoring()
  } else {
    startMonitoring()
  }
}

// 开始监控
const startMonitoring = () => {
  isMonitoring.value = true
  monitoringInterval.value = setInterval(async () => {
    try {
      await auditAdminStore.loadRealtimeOperations()
      // 计算每分钟操作数
      const now = new Date()
      const oneMinuteAgo = new Date(now.getTime() - 60000)
      const recentOperations = realtimeOperations.value.filter(op =>
        new Date(op.timestamp) > oneMinuteAgo
      )
      operationsPerMinute.value = recentOperations.length
    } catch (error) {
      console.error('实时监控数据加载失败:', error)
    }
  }, 5000) // 每5秒刷新一次

  ElMessage.success('开始实时监控')
}

// 停止监控
const stopMonitoring = () => {
  isMonitoring.value = false
  if (monitoringInterval.value) {
    clearInterval(monitoringInterval.value)
    monitoringInterval.value = null
  }
  operationsPerMinute.value = 0
  ElMessage.info('停止实时监控')
}

// 清空操作记录
const clearOperations = () => {
  auditAdminStore.realtimeOperations = []
  ElMessage.success('已清空操作记录')
}

// 加载异常告警
const loadAnomalyAlerts = async () => {
  try {
    await auditAdminStore.loadAnomalyAlerts()
  } catch (error) {
    console.error('加载异常告警失败:', error)
    ElMessage.error('加载异常告警失败')
  }
}

// 加载活跃用户监控
const loadActiveUsersMonitor = async () => {
  try {
    await auditAdminStore.loadActiveUsersMonitor()
  } catch (error) {
    console.error('加载活跃用户监控失败:', error)
    ElMessage.error('加载活跃用户监控失败')
  }
}

// 查看告警详情
const viewAlertDetail = async (alert) => {
  try {
    const response = await auditAdminStore.getAlertDetail(alert.id)
    currentAlert.value = response.data || alert
    alertDetailDialogVisible.value = true
  } catch (error) {
    console.error('获取告警详情失败:', error)
    ElMessage.error('获取告警详情失败')
  }
}

// 标记告警为已处理
const markAlertAsResolved = async (alertId) => {
  try {
    await ElMessageBox.confirm(
      '确定要标记此告警为已处理吗？',
      '确认标记',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    await auditAdminStore.markAlertAsResolved(alertId)
    ElMessage.success('标记成功')
    await loadAnomalyAlerts()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('标记告警失败:', error)
      ElMessage.error('标记告警失败')
    }
  }
}

// 标记当前告警为已处理
const markCurrentAlertAsResolved = async () => {
  if (!currentAlert.value) return

  try {
    await auditAdminStore.markAlertAsResolved(currentAlert.value.id)
    alertDetailDialogVisible.value = false
    ElMessage.success('标记成功')
    await loadAnomalyAlerts()
  } catch (error) {
    console.error('标记告警失败:', error)
    ElMessage.error('标记告警失败')
  }
}

// 格式化时间
const formatTime = (timestamp) => {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleTimeString('zh-CN')
}

// 格式化日期时间
const formatDateTime = (timestamp) => {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return date.toLocaleString('zh-CN')
}

// 获取操作类型标签
const getOperationTypeTag = (type) => {
  const tagMap = {
    'login': 'primary',
    'logout': 'info',
    'create': 'success',
    'update': 'warning',
    'delete': 'danger',
    'read': ''
  }
  return tagMap[type] || 'info'
}

// 获取操作类型标签文本
const getOperationTypeLabel = (type) => {
  const labelMap = {
    'login': '登录',
    'logout': '登出',
    'create': '创建',
    'update': '更新',
    'delete': '删除',
    'read': '读取'
  }
  return labelMap[type] || type
}

// 获取严重程度标签
const getSeverityTag = (severity) => {
  const tagMap = {
    'critical': 'danger',
    'warning': 'warning',
    'info': 'info'
  }
  return tagMap[severity] || 'info'
}

// 获取严重程度标签文本
const getSeverityLabel = (severity) => {
  const labelMap = {
    'critical': '严重',
    'warning': '警告',
    'info': '信息'
  }
  return labelMap[severity] || severity
}

// 格式化详细信息
const formatDetails = (details) => {
  if (typeof details === 'string') {
    try {
      return JSON.stringify(JSON.parse(details), null, 2)
    } catch {
      return details
    }
  } else if (typeof details === 'object') {
    return JSON.stringify(details, null, 2)
  }
  return details
}

onMounted(() => {
  initData()
})

onUnmounted(() => {
  stopMonitoring()
})
</script>

<style scoped>
.operation-monitor {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.page-title {
  font-size: 24px;
  font-weight: 600;
  color: #303133;
  margin: 0;
}

.system-status {
  margin-bottom: 20px;
}

.status-card {
  height: 120px;
}

.status-content {
  display: flex;
  align-items: center;
  height: 100%;
}

.status-icon {
  width: 60px;
  height: 60px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 16px;
  font-size: 24px;
  color: white;
}

.status-icon.system-health {
  background-color: #67C23A;
}

.status-icon.active-users {
  background-color: #409EFF;
}

.status-icon.operations-rate {
  background-color: #E6A23C;
}

.status-icon.anomaly-count {
  background-color: #F56C6C;
}

.status-value {
  font-size: 28px;
  font-weight: 600;
  color: #303133;
  line-height: 1;
}

.status-label {
  font-size: 14px;
  color: #909399;
  margin-top: 8px;
}

.realtime-operations {
  margin-bottom: 20px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.operations-container {
  max-height: 400px;
  overflow-y: auto;
}

.operation-item {
  display: flex;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid #ebeef5;
  transition: background-color 0.3s;
}

.operation-item:hover {
  background-color: #f5f7fa;
}

.operation-item.critical {
  background-color: #fef0f0;
  border-left: 3px solid #f56c6c;
  padding-left: 8px;
}

.operation-time {
  width: 80px;
  font-size: 12px;
  color: #909399;
}

.operation-user {
  width: 120px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.username {
  font-weight: 500;
}

.operation-type {
  width: 100px;
}

.operation-description {
  flex: 1;
  padding: 0 16px;
}

.operation-status {
  width: 80px;
}

.operation-ip {
  width: 120px;
  font-size: 12px;
  color: #909399;
}

.empty-operations {
  padding: 40px 0;
}

.anomaly-alerts {
  margin-bottom: 20px;
}

.active-users-monitor {
  margin-bottom: 20px;
}

.users-container {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 16px;
}

.user-item {
  display: flex;
  align-items: center;
  padding: 16px;
  border: 1px solid #ebeef5;
  border-radius: 4px;
  transition: all 0.3s;
}

.user-item:hover {
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.user-avatar {
  margin-right: 12px;
}

.user-info {
  flex: 1;
}

.username {
  font-weight: 500;
  margin-bottom: 4px;
}

.user-stats {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.operation-count {
  font-size: 12px;
  color: #409EFF;
}

.last-active {
  font-size: 12px;
  color: #909399;
}

.user-status {
  margin-left: auto;
}

.empty-users {
  grid-column: 1 / -1;
  padding: 40px 0;
}

pre {
  background-color: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  font-size: 14px;
  line-height: 1.5;
  overflow-x: auto;
}
</style>