<template>
  <div class="audit-admin-dashboard">
    <!-- 页面头部 -->
    <div class="page-header">
      <h1 class="page-title">审计概览</h1>
      <div class="page-actions">
        <el-button type="primary" @click="refreshData">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
      </div>
    </div>

    <!-- 统计卡片 -->
    <div class="stats-cards">
      <el-row :gutter="20">
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon total-logs">
                <el-icon><Document /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ auditStats.totalLogs || 0 }}</div>
                <div class="stat-label">总审计日志</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon today-logs">
                <el-icon><Calendar /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ auditStats.todayLogs || 0 }}</div>
                <div class="stat-label">今日日志</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon critical-alerts">
                <el-icon><Warning /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ auditStats.criticalAlerts || 0 }}</div>
                <div class="stat-label">严重告警</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon active-users">
                <el-icon><User /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ auditStats.activeUsers || 0 }}</div>
                <div class="stat-label">活跃用户</div>
              </div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- 图表区域 -->
    <div class="charts-section">
      <el-row :gutter="20">
        <!-- 操作类型分布 -->
        <el-col :xs="24" :sm="12" :md="12" :lg="12">
          <el-card class="chart-card">
            <template #header>
              <div class="chart-header">
                <span>操作类型分布</span>
                <el-button text @click="loadOperationTypeStats">
                  <el-icon><Refresh /></el-icon>
                </el-button>
              </div>
            </template>
            <div v-loading="statisticsLoading" class="chart-container">
              <div v-if="operationTypeStats.length === 0" class="empty-chart">
                <el-empty description="暂无数据" />
              </div>
              <div v-else ref="operationTypeChart" class="chart"></div>
            </div>
          </el-card>
        </el-col>

        <!-- 时间趋势分析 -->
        <el-col :xs="24" :sm="12" :md="12" :lg="12">
          <el-card class="chart-card">
            <template #header>
              <div class="chart-header">
                <span>时间趋势分析</span>
                <el-button text @click="loadTimeTrendStats">
                  <el-icon><Refresh /></el-icon>
                </el-button>
              </div>
            </template>
            <div v-loading="statisticsLoading" class="chart-container">
              <div v-if="timeTrendStats.length === 0" class="empty-chart">
                <el-empty description="暂无数据" />
              </div>
              <div v-else ref="timeTrendChart" class="chart"></div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- 最近操作记录 -->
    <div class="recent-operations">
      <el-card>
        <template #header>
          <div class="section-header">
            <span>最近操作记录</span>
            <el-button type="primary" text @click="$router.push('/audit-admin/logs')">
              查看全部
            </el-button>
          </div>
        </template>
        <div v-loading="auditLogsLoading">
          <el-table :data="recentOperations" style="width: 100%">
            <el-table-column prop="timestamp" label="时间" width="180">
              <template #default="{ row }">
                {{ formatDateTime(row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="username" label="用户" width="120" />
            <el-table-column prop="operation_type" label="操作类型" width="120">
              <template #default="{ row }">
                <el-tag :type="getOperationTypeTag(row.operation_type)">
                  {{ row.operation_type }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="description" label="操作描述" />
            <el-table-column prop="status" label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="row.status === 'success' ? 'success' : 'danger'">
                  {{ row.status === 'success' ? '成功' : '失败' }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { useAuditAdminStore } from '@/store/modules/audit_admin'
import { Refresh, Document, Calendar, Warning, User } from '@element-plus/icons-vue'
import * as echarts from 'echarts'

const router = useRouter()
const auditAdminStore = useAuditAdminStore()

// 图表引用
const operationTypeChart = ref(null)
const timeTrendChart = ref(null)

// 计算属性
const auditStats = computed(() => auditAdminStore.auditStats)
const recentOperations = computed(() => auditAdminStore.auditLogs.slice(0, 10))

// 初始化数据
const initData = async () => {
  try {
    await Promise.all([
      auditAdminStore.loadAuditLogs(),
      auditAdminStore.loadStatisticsOverview(),
      auditAdminStore.loadOperationTypeStats(),
      auditAdminStore.loadTimeTrendStats(),
      auditAdminStore.loadAlerts()
    ])
  } catch (error) {
    console.error('初始化数据失败:', error)
  }
}

// 刷新数据
const refreshData = async () => {
  await initData()
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

// 初始化操作类型分布图表
const initOperationTypeChart = () => {
  if (!operationTypeChart.value || auditAdminStore.operationTypeStats.length === 0) return

  const chart = echarts.init(operationTypeChart.value)
  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      left: 'left',
      data: auditAdminStore.operationTypeStats.map(item => item.operation_type)
    },
    series: [
      {
        name: '操作类型',
        type: 'pie',
        radius: ['50%', '70%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 10,
          borderColor: '#fff',
          borderWidth: 2
        },
        label: {
          show: false,
          position: 'center'
        },
        emphasis: {
          label: {
            show: true,
            fontSize: '18',
            fontWeight: 'bold'
          }
        },
        labelLine: {
          show: false
        },
        data: auditAdminStore.operationTypeStats.map(item => ({
          value: item.count,
          name: item.operation_type
        }))
      }
    ]
  }

  chart.setOption(option)
}

// 初始化时间趋势图表
const initTimeTrendChart = () => {
  if (!timeTrendChart.value || auditAdminStore.timeTrendStats.length === 0) return

  const chart = echarts.init(timeTrendChart.value)
  const option = {
    tooltip: {
      trigger: 'axis'
    },
    legend: {
      data: ['操作数量']
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: auditAdminStore.timeTrendStats.map(item => item.time_period)
    },
    yAxis: {
      type: 'value'
    },
    series: [
      {
        name: '操作数量',
        type: 'line',
        smooth: true,
        data: auditAdminStore.timeTrendStats.map(item => item.count),
        itemStyle: {
          color: '#409EFF'
        },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(64, 158, 255, 0.3)' },
            { offset: 1, color: 'rgba(64, 158, 255, 0.1)' }
          ])
        }
      }
    ]
  }

  chart.setOption(option)
}

// 加载操作类型统计
const loadOperationTypeStats = async () => {
  try {
    await auditAdminStore.loadOperationTypeStats()
    nextTick(() => {
      initOperationTypeChart()
    })
  } catch (error) {
    console.error('加载操作类型统计失败:', error)
  }
}

// 加载时间趋势统计
const loadTimeTrendStats = async () => {
  try {
    await auditAdminStore.loadTimeTrendStats()
    nextTick(() => {
      initTimeTrendChart()
    })
  } catch (error) {
    console.error('加载时间趋势统计失败:', error)
  }
}

onMounted(async () => {
  await initData()
  nextTick(() => {
    initOperationTypeChart()
    initTimeTrendChart()
  })
})
</script>

<style scoped>
.audit-admin-dashboard {
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

.stats-cards {
  margin-bottom: 20px;
}

.stat-card {
  height: 120px;
}

.stat-content {
  display: flex;
  align-items: center;
  height: 100%;
}

.stat-icon {
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

.stat-icon.total-logs {
  background-color: #409EFF;
}

.stat-icon.today-logs {
  background-color: #67C23A;
}

.stat-icon.critical-alerts {
  background-color: #F56C6C;
}

.stat-icon.active-users {
  background-color: #E6A23C;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  color: #303133;
  line-height: 1;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-top: 8px;
}

.charts-section {
  margin-bottom: 20px;
}

.chart-card {
  height: 400px;
}

.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.chart-container {
  height: 320px;
}

.chart {
  width: 100%;
  height: 100%;
}

.empty-chart {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.recent-operations {
  margin-bottom: 20px;
}
</style>