<template>
  <el-card class="chart-card" :style="{ height: height + 'px' }">
    <!-- 图表头部 -->
    <template #header>
      <div class="chart-header">
        <span class="chart-title">{{ title }}</span>
        <div class="chart-actions">
          <slot name="actions">
            <el-button v-if="showRefresh" text @click="$emit('refresh')">
              <el-icon><Refresh /></el-icon>
            </el-button>
          </slot>
        </div>
      </div>
    </template>

    <!-- 图表内容 -->
    <div v-loading="loading" class="chart-container">
      <div v-if="!data || data.length === 0" class="empty-chart">
        <el-empty :description="emptyText" />
      </div>
      <div v-else ref="chartRef" class="chart"></div>
    </div>
  </el-card>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import * as echarts from 'echarts'

const props = defineProps({
  // 基础配置
  title: {
    type: String,
    default: ''
  },
  data: {
    type: Array,
    default: () => []
  },
  loading: {
    type: Boolean,
    default: false
  },

  // 样式配置
  height: {
    type: Number,
    default: 400
  },
  showRefresh: {
    type: Boolean,
    default: true
  },
  emptyText: {
    type: String,
    default: '暂无数据'
  },

  // ECharts配置
  option: {
    type: Object,
    default: () => ({})
  },
  chartType: {
    type: String,
    default: 'line'
  },
  theme: {
    type: String,
    default: ''
  }
})

const emit = defineEmits(['refresh'])

// 图表引用
const chartRef = ref()
let chartInstance = null

// 初始化图表
const initChart = () => {
  if (!chartRef.value || !props.data || props.data.length === 0) return

  // 销毁现有实例
  if (chartInstance) {
    chartInstance.dispose()
  }

  // 创建新实例
  chartInstance = echarts.init(chartRef.value, props.theme)

  // 设置配置项
  const defaultOption = getDefaultOption()
  const mergedOption = { ...defaultOption, ...props.option }
  chartInstance.setOption(mergedOption)

  // 监听窗口大小变化
  window.addEventListener('resize', handleResize)
}

// 获取默认配置
const getDefaultOption = () => {
  const baseOption = {
    tooltip: {
      trigger: 'axis'
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      boundaryGap: false
    },
    yAxis: {
      type: 'value'
    },
    series: [
      {
        type: props.chartType,
        smooth: true,
        data: props.data
      }
    ]
  }

  return baseOption
}

// 处理窗口大小变化
const handleResize = () => {
  if (chartInstance) {
    chartInstance.resize()
  }
}

// 监听数据变化
watch(() => props.data, () => {
  nextTick(() => {
    initChart()
  })
}, { deep: true })

// 生命周期
onMounted(() => {
  nextTick(() => {
    initChart()
  })
})

onUnmounted(() => {
  if (chartInstance) {
    chartInstance.dispose()
    chartInstance = null
  }
  window.removeEventListener('resize', handleResize)
})

// 暴露方法给父组件
defineExpose({
  getChartInstance: () => chartInstance,
  resize: handleResize
})
</script>

<style scoped>
.chart-card {
  margin-bottom: 16px;
}

.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.chart-title {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.chart-container {
  height: calc(100% - 60px);
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