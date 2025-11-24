<template>
  <div class="statistics">
    <!-- 页面头部 -->
    <div class="page-header">
      <h1 class="page-title">统计分析</h1>
      <div class="page-actions">
        <el-button type="primary" @click="generateReport">
          <el-icon><Document /></el-icon>
          生成报告
        </el-button>
        <el-button @click="refreshData">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
      </div>
    </div>

    <!-- 时间范围选择 -->
    <el-card class="filter-card">
      <el-form :model="filterForm" label-width="80px">
        <el-row :gutter="20">
          <el-col :xs="24" :sm="12" :md="8" :lg="6">
            <el-form-item label="时间范围">
              <el-date-picker
                v-model="filterForm.dateRange"
                type="daterange"
                range-separator="至"
                start-placeholder="开始日期"
                end-placeholder="结束日期"
                value-format="YYYY-MM-DD"
                @change="handleDateRangeChange"
                style="width: 100%"
              />
            </el-form-item>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="6">
            <el-form-item label="统计粒度">
              <el-select
                v-model="filterForm.granularity"
                placeholder="请选择统计粒度"
                @change="handleGranularityChange"
                style="width: 100%"
              >
                <el-option label="按小时" value="hourly" />
                <el-option label="按天" value="daily" />
                <el-option label="按周" value="weekly" />
                <el-option label="按月" value="monthly" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="6">
            <el-form-item label="图表类型">
              <el-select
                v-model="filterForm.chartType"
                placeholder="请选择图表类型"
                @change="handleChartTypeChange"
                style="width: 100%"
              >
                <el-option label="柱状图" value="bar" />
                <el-option label="折线图" value="line" />
                <el-option label="饼图" value="pie" />
                <el-option label="面积图" value="area" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>
      </el-form>
    </el-card>

    <!-- 统计指标卡片 -->
    <div class="stats-cards">
      <el-row :gutter="20">
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon total-operations">
                <el-icon><Operation /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ statisticsOverview.total_operations || 0 }}</div>
                <div class="stat-label">总操作数</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon success-rate">
                <el-icon><SuccessFilled /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ statisticsOverview.success_rate || 0 }}%</div>
                <div class="stat-label">成功率</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon unique-users">
                <el-icon><User /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ statisticsOverview.unique_users || 0 }}</div>
                <div class="stat-label">活跃用户数</div>
              </div>
            </div>
          </el-card>
        </el-col>
        <el-col :xs="12" :sm="6" :md="6" :lg="6">
          <el-card class="stat-card">
            <div class="stat-content">
              <div class="stat-icon avg-response">
                <el-icon><Clock /></el-icon>
              </div>
              <div class="stat-info">
                <div class="stat-value">{{ statisticsOverview.avg_response_time || 0 }}ms</div>
                <div class="stat-label">平均响应时间</div>
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

        <!-- 用户活跃度分析 -->
        <el-col :xs="24" :sm="12" :md="12" :lg="12">
          <el-card class="chart-card">
            <template #header>
              <div class="chart-header">
                <span>用户活跃度分析</span>
                <el-button text @click="loadUserActivityStats">
                  <el-icon><Refresh /></el-icon>
                </el-button>
              </div>
            </template>
            <div v-loading="statisticsLoading" class="chart-container">
              <div v-if="userActivityStats.length === 0" class="empty-chart">
                <el-empty description="暂无数据" />
              </div>
              <div v-else ref="userActivityChart" class="chart"></div>
            </div>
          </el-card>
        </el-col>

        <!-- 时间趋势分析 -->
        <el-col :xs="24" :sm="24" :md="24" :lg="24">
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

        <!-- 异常操作分析 -->
        <el-col :xs="24" :sm="12" :md="12" :lg="12">
          <el-card class="chart-card">
            <template #header>
              <div class="chart-header">
                <span>异常操作分析</span>
                <el-button text @click="loadAnomalyStats">
                  <el-icon><Refresh /></el-icon>
                </el-button>
              </div>
            </template>
            <div v-loading="statisticsLoading" class="chart-container">
              <div v-if="anomalyStats.length === 0" class="empty-chart">
                <el-empty description="暂无数据" />
              </div>
              <div v-else ref="anomalyChart" class="chart"></div>
            </div>
          </el-card>
        </el-col>

        <!-- 风险事件统计 -->
        <el-col :xs="24" :sm="12" :md="12" :lg="12">
          <el-card class="chart-card">
            <template #header>
              <div class="chart-header">
                <span>风险事件统计</span>
                <el-button text @click="loadRiskEventStats">
                  <el-icon><Refresh /></el-icon>
                </el-button>
              </div>
            </template>
            <div v-loading="statisticsLoading" class="chart-container">
              <div v-if="riskEventStats.length === 0" class="empty-chart">
                <el-empty description="暂无数据" />
              </div>
              <div v-else ref="riskEventChart" class="chart"></div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import { Document, Refresh, Operation, SuccessFilled, User, Clock } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
import { useAuditAdminStore } from '@/store/modules/audit_admin'

const auditAdminStore = useAuditAdminStore()

// 筛选表单
const filterForm = reactive({
  dateRange: [],
  granularity: 'daily',
  chartType: 'bar'
})

// 图表引用
const operationTypeChart = ref(null)
const userActivityChart = ref(null)
const timeTrendChart = ref(null)
const anomalyChart = ref(null)
const riskEventChart = ref(null)

// 统计状态
const statisticsOverview = ref({})
const operationTypeStats = ref([])
const userActivityStats = ref([])
const timeTrendStats = ref([])
const anomalyStats = ref([])
const riskEventStats = ref([])
const statisticsLoading = ref(false)

// 初始化数据
const initData = async () => {
  try {
    statisticsLoading.value = true
    await Promise.all([
      loadStatisticsOverview(),
      loadOperationTypeStats(),
      loadUserActivityStats(),
      loadTimeTrendStats(),
      loadAnomalyStats(),
      loadRiskEventStats()
    ])
  } catch (error) {
    console.error('初始化数据失败:', error)
    ElMessage.error('初始化数据失败')
  } finally {
    statisticsLoading.value = false
  }
}

// 刷新数据
const refreshData = async () => {
  await initData()
}

// 加载统计概览
const loadStatisticsOverview = async () => {
  try {
    const response = await auditAdminStore.loadStatisticsOverview()
    statisticsOverview.value = response.data || {}
  } catch (error) {
    console.error('加载统计概览失败:', error)
    throw error
  }
}

// 加载操作类型统计
const loadOperationTypeStats = async () => {
  try {
    const params = buildQueryParams()
    const response = await auditAdminStore.loadOperationTypeStats(params)
    operationTypeStats.value = response.data || []
    nextTick(() => {
      initOperationTypeChart()
    })
  } catch (error) {
    console.error('加载操作类型统计失败:', error)
    throw error
  }
}

// 加载用户活动统计
const loadUserActivityStats = async () => {
  try {
    const params = buildQueryParams()
    const response = await auditAdminStore.loadUserActivityStats(params)
    userActivityStats.value = response.data || []
    nextTick(() => {
      initUserActivityChart()
    })
  } catch (error) {
    console.error('加载用户活动统计失败:', error)
    throw error
  }
}

// 加载时间趋势统计
const loadTimeTrendStats = async () => {
  try {
    const params = buildQueryParams()
    const response = await auditAdminStore.loadTimeTrendStats(params)
    timeTrendStats.value = response.data || []
    nextTick(() => {
      initTimeTrendChart()
    })
  } catch (error) {
    console.error('加载时间趋势统计失败:', error)
    throw error
  }
}

// 加载异常统计
const loadAnomalyStats = async () => {
  try {
    const params = buildQueryParams()
    const response = await auditAdminStore.loadAnomalyAlerts(params)
    anomalyStats.value = response.data || []
    nextTick(() => {
      initAnomalyChart()
    })
  } catch (error) {
    console.error('加载异常统计失败:', error)
    throw error
  }
}

// 加载风险事件统计
const loadRiskEventStats = async () => {
  try {
    const params = buildQueryParams()
    const response = await auditAdminStore.loadAlerts(params)
    riskEventStats.value = response.data || []
    nextTick(() => {
      initRiskEventChart()
    })
  } catch (error) {
    console.error('加载风险事件统计失败:', error)
    throw error
  }
}

// 构建查询参数
const buildQueryParams = () => {
  const params = {}

  if (filterForm.dateRange && filterForm.dateRange.length === 2) {
    params.start_date = filterForm.dateRange[0]
    params.end_date = filterForm.dateRange[1]
  }

  if (filterForm.granularity) {
    params.granularity = filterForm.granularity
  }

  return params
}

// 时间范围变更处理
const handleDateRangeChange = () => {
  initData()
}

// 统计粒度变更处理
const handleGranularityChange = () => {
  initData()
}

// 图表类型变更处理
const handleChartTypeChange = () => {
  // 重新初始化所有图表
  nextTick(() => {
    initOperationTypeChart()
    initUserActivityChart()
    initTimeTrendChart()
    initAnomalyChart()
    initRiskEventChart()
  })
}

// 生成报告
const generateReport = async () => {
  try {
    const reportParams = buildQueryParams()
    await auditAdminStore.generateAuditReport(reportParams)
    ElMessage.success('报告生成成功')
  } catch (error) {
    console.error('生成报告失败:', error)
    ElMessage.error('生成报告失败')
  }
}

// 初始化操作类型分布图表
const initOperationTypeChart = () => {
  if (!operationTypeChart.value || operationTypeStats.value.length === 0) return

  const chart = echarts.init(operationTypeChart.value)
  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      left: 'left',
      data: operationTypeStats.value.map(item => item.operation_type)
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
        data: operationTypeStats.value.map(item => ({
          value: item.count,
          name: item.operation_type
        }))
      }
    ]
  }

  chart.setOption(option)
}

// 初始化用户活跃度图表
const initUserActivityChart = () => {
  if (!userActivityChart.value || userActivityStats.value.length === 0) return

  const chart = echarts.init(userActivityChart.value)
  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'shadow'
      }
    },
    legend: {
      data: ['操作次数']
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: userActivityStats.value.map(item => item.username)
    },
    yAxis: {
      type: 'value'
    },
    series: [
      {
        name: '操作次数',
        type: filterForm.chartType,
        data: userActivityStats.value.map(item => item.operation_count),
        itemStyle: {
          color: '#409EFF'
        }
      }
    ]
  }

  chart.setOption(option)
}

// 初始化时间趋势图表
const initTimeTrendChart = () => {
  if (!timeTrendChart.value || timeTrendStats.value.length === 0) return

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
      data: timeTrendStats.value.map(item => item.time_period)
    },
    yAxis: {
      type: 'value'
    },
    series: [
      {
        name: '操作数量',
        type: filterForm.chartType,
        smooth: true,
        data: timeTrendStats.value.map(item => item.count),
        itemStyle: {
          color: '#67C23A'
        },
        areaStyle: filterForm.chartType === 'area' ? {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(103, 194, 58, 0.3)' },
            { offset: 1, color: 'rgba(103, 194, 58, 0.1)' }
          ])
        } : undefined
      }
    ]
  }

  chart.setOption(option)
}

// 初始化异常操作图表
const initAnomalyChart = () => {
  if (!anomalyChart.value || anomalyStats.value.length === 0) return

  const chart = echarts.init(anomalyChart.value)
  const option = {
    tooltip: {
      trigger: 'axis'
    },
    legend: {
      data: ['异常操作']
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: anomalyStats.value.map(item => item.operation_type)
    },
    yAxis: {
      type: 'value'
    },
    series: [
      {
        name: '异常操作',
        type: filterForm.chartType,
        data: anomalyStats.value.map(item => item.count),
        itemStyle: {
          color: '#F56C6C'
        }
      }
    ]
  }

  chart.setOption(option)
}

// 初始化风险事件图表
const initRiskEventChart = () => {
  if (!riskEventChart.value || riskEventStats.value.length === 0) return

  const chart = echarts.init(riskEventChart.value)
  const option = {
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      left: 'left',
      data: riskEventStats.value.map(item => item.severity)
    },
    series: [
      {
        name: '风险事件',
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
        data: riskEventStats.value.map(item => ({
          value: item.count,
          name: item.severity
        }))
      }
    ]
  }

  chart.setOption(option)
}

onMounted(async () => {
  await initData()
})
</script>

<style scoped>
.statistics {
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

.filter-card {
  margin-bottom: 20px;
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

.stat-icon.total-operations {
  background-color: #409EFF;
}

.stat-icon.success-rate {
  background-color: #67C23A;
}

.stat-icon.unique-users {
  background-color: #E6A23C;
}

.stat-icon.avg-response {
  background-color: #909399;
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
  margin-bottom: 20px;
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
</style>