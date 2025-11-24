<template>
  <div class="dashboard-container">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1 class="page-title">仪表板</h1>
      <p class="page-description">欢迎回来，{{ authStore.displayName }}</p>
    </div>

    <!-- 统计卡片 -->
    <div class="stats-cards">
      <el-row :gutter="20">
        <!-- 系统管理员统计 -->
        <template v-if="authStore.userRole === 'sys_admin'">
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon user-icon">
                  <el-icon><User /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.totalUsers || 0 }}</div>
                  <div class="stat-label">总用户数</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon key-icon">
                  <el-icon><Key /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.activeApiKeys || 0 }}</div>
                  <div class="stat-label">活跃API密钥</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon model-icon">
                  <el-icon><Cpu /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.totalModels || 0 }}</div>
                  <div class="stat-label">模型数量</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon group-icon">
                  <el-icon><UserGroup /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.totalGroups || 0 }}</div>
                  <div class="stat-label">用户组数</div>
                </div>
              </div>
            </el-card>
          </el-col>
        </template>

        <!-- 安全管理员统计 -->
        <template v-if="authStore.userRole === 'auth_admin'">
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon security-icon">
                  <el-icon><Lock /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.securityEvents || 0 }}</div>
                  <div class="stat-label">安全事件</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon ip-icon">
                  <el-icon><Monitor /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.whitelistedIPs || 0 }}</div>
                  <div class="stat-label">IP白名单</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon policy-icon">
                  <el-icon><Document /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.activePolicies || 0 }}</div>
                  <div class="stat-label">安全策略</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon audit-icon">
                  <el-icon><Search /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.passwordChanges || 0 }}</div>
                  <div class="stat-label">密码变更</div>
                </div>
              </div>
            </el-card>
          </el-col>
        </template>

        <!-- 审计管理员统计 -->
        <template v-if="authStore.userRole === 'audit_admin'">
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon log-icon">
                  <el-icon><Notebook /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.totalLogs || 0 }}</div>
                  <div class="stat-label">总日志数</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon warning-icon">
                  <el-icon><Warning /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.warningLogs || 0 }}</div>
                  <div class="stat-label">警告日志</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon error-icon">
                  <el-icon><CircleClose /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.errorLogs || 0 }}</div>
                  <div class="stat-label">错误日志</div>
                </div>
              </div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon admin-icon">
                  <el-icon><UserFilled /></el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-value">{{ stats.adminActions || 0 }}</div>
                  <div class="stat-label">管理员操作</div>
                </div>
              </div>
            </el-card>
          </el-col>
        </template>
      </el-row>
    </div>

    <!-- 最近活动 -->
    <div class="recent-activity">
      <el-card class="activity-card">
        <template #header>
          <div class="card-header">
            <span>最近活动</span>
          </div>
        </template>
        <div class="activity-list">
          <div v-if="recentActivities.length === 0" class="empty-state">
            <el-empty description="暂无活动记录" />
          </div>
          <div v-else>
            <el-timeline>
              <el-timeline-item
                v-for="activity in recentActivities"
                :key="activity.id"
                :timestamp="activity.timestamp"
                :type="getActivityType(activity.level)"
              >
                <div class="activity-item">
                  <div class="activity-content">
                    <div class="activity-message">{{ activity.message }}</div>
                    <div class="activity-meta">
                      <span class="activity-user">{{ activity.username }}</span>
                      <span class="activity-ip">{{ activity.ip_address }}</span>
                    </div>
                  </div>
                </div>
              </el-timeline-item>
            </el-timeline>
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  User,
  Key,
  Cpu,
  UserGroup,
  Lock,
  Monitor,
  Document,
  Search,
  Notebook,
  Warning,
  CircleClose,
  UserFilled
} from '@element-plus/icons-vue'
import { useAuthStore } from '@/store/modules/auth'

const authStore = useAuthStore()

// 统计数据
const stats = reactive({
  // 系统管理员统计
  totalUsers: 0,
  activeApiKeys: 0,
  totalModels: 0,
  totalGroups: 0,

  // 安全管理员统计
  securityEvents: 0,
  whitelistedIPs: 0,
  activePolicies: 0,
  passwordChanges: 0,

  // 审计管理员统计
  totalLogs: 0,
  warningLogs: 0,
  errorLogs: 0,
  adminActions: 0
})

// 最近活动
const recentActivities = ref([])

// 获取活动类型
const getActivityType = (level) => {
  const typeMap = {
    'INFO': 'primary',
    'WARNING': 'warning',
    'ERROR': 'danger',
    'SUCCESS': 'success'
  }
  return typeMap[level] || 'primary'
}

// 加载统计数据
const loadStats = async () => {
  try {
    // 这里应该调用实际的API获取统计数据
    // 暂时使用模拟数据
    if (authStore.userRole === 'sys_admin') {
      stats.totalUsers = 156
      stats.activeApiKeys = 42
      stats.totalModels = 28
      stats.totalGroups = 12
    } else if (authStore.userRole === 'auth_admin') {
      stats.securityEvents = 8
      stats.whitelistedIPs = 24
      stats.activePolicies = 6
      stats.passwordChanges = 15
    } else if (authStore.userRole === 'audit_admin') {
      stats.totalLogs = 1256
      stats.warningLogs = 34
      stats.errorLogs = 12
      stats.adminActions = 89
    }
  } catch (error) {
    console.error('加载统计数据失败:', error)
    ElMessage.error('加载统计数据失败')
  }
}

// 加载最近活动
const loadRecentActivities = async () => {
  try {
    // 这里应该调用实际的API获取最近活动
    // 暂时使用模拟数据
    recentActivities.value = [
      {
        id: 1,
        timestamp: '2024-01-15 10:30:25',
        level: 'INFO',
        message: '用户登录系统',
        username: authStore.userName,
        ip_address: '192.168.1.100'
      },
      {
        id: 2,
        timestamp: '2024-01-15 10:25:18',
        level: 'SUCCESS',
        message: '密码修改成功',
        username: authStore.userName,
        ip_address: '192.168.1.100'
      },
      {
        id: 3,
        timestamp: '2024-01-15 09:45:32',
        level: 'WARNING',
        message: '检测到可疑登录尝试',
        username: 'unknown',
        ip_address: '192.168.1.150'
      }
    ]
  } catch (error) {
    console.error('加载最近活动失败:', error)
    ElMessage.error('加载最近活动失败')
  }
}

// 初始化
onMounted(async () => {
  await Promise.all([
    loadStats(),
    loadRecentActivities()
  ])
})
</script>

<style scoped>
.dashboard-container {
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
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.stat-content {
  display: flex;
  align-items: center;
  padding: 16px;
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
  color: #fff;
}

.user-icon { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.key-icon { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
.model-icon { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
group-icon { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }
.security-icon { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
ip-icon { background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); }
policy-icon { background: linear-gradient(135deg, #d299c2 0%, #fef9d7 100%); }
audit-icon { background: linear-gradient(135deg, #89f7fe 0%, #66a6ff 100%); }
log-icon { background: linear-gradient(135deg, #fd746c 0%, #ff9068 100%); }
warning-icon { background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); }
error-icon { background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%); }
admin-icon { background: linear-gradient(135deg, #a1c4fd 0%, #c2e9fb 100%); }

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  color: #303133;
  line-height: 1;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
}

.activity-card {
  border-radius: 8px;
  border: none;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.card-header {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.activity-list {
  max-height: 400px;
  overflow-y: auto;
}

.activity-item {
  padding: 8px 0;
}

.activity-content {
  display: flex;
  flex-direction: column;
}

.activity-message {
  font-size: 14px;
  color: #303133;
  margin-bottom: 4px;
}

.activity-meta {
  display: flex;
  gap: 12px;
  font-size: 12px;
  color: #909399;
}

.activity-user {
  font-weight: 500;
}

.empty-state {
  padding: 40px 0;
  text-align: center;
}
</style>