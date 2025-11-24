<template>
  <el-card class="status-card" :style="{ height: height + 'px' }">
    <div class="status-content">
      <!-- 图标区域 -->
      <div class="status-icon" :class="iconClass" :style="{ backgroundColor: iconColor }">
        <slot name="icon">
          <el-icon :size="iconSize">
            <component :is="icon" />
          </el-icon>
        </slot>
      </div>

      <!-- 信息区域 -->
      <div class="status-info">
        <div class="status-value" :style="{ color: valueColor }">
          {{ value }}
        </div>
        <div class="status-label">
          {{ label }}
        </div>
        <div v-if="description" class="status-description">
          {{ description }}
        </div>
      </div>

      <!-- 操作区域 -->
      <div v-if="$slots.actions" class="status-actions">
        <slot name="actions"></slot>
      </div>
    </div>
  </el-card>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  // 基础配置
  value: {
    type: [String, Number],
    default: ''
  },
  label: {
    type: String,
    default: ''
  },
  description: {
    type: String,
    default: ''
  },

  // 样式配置
  height: {
    type: Number,
    default: 120
  },
  icon: {
    type: String,
    default: ''
  },
  iconSize: {
    type: Number,
    default: 24
  },
  iconColor: {
    type: String,
    default: '#409EFF'
  },
  valueColor: {
    type: String,
    default: '#303133'
  },

  // 预设样式
  type: {
    type: String,
    default: 'primary',
    validator: (value) => ['primary', 'success', 'warning', 'danger', 'info'].includes(value)
  }
})

// 计算图标样式类
const iconClass = computed(() => {
  return `status-icon-${props.type}`
})

// 预设颜色映射
const presetColors = {
  primary: '#409EFF',
  success: '#67C23A',
  warning: '#E6A23C',
  danger: '#F56C6C',
  info: '#909399'
}

// 计算图标颜色
const iconColor = computed(() => {
  return presetColors[props.type] || props.iconColor
})
</script>

<style scoped>
.status-card {
  transition: all 0.3s;
}

.status-card:hover {
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
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
  color: white;
  transition: all 0.3s;
}

.status-icon:hover {
  transform: scale(1.05);
}

.status-info {
  flex: 1;
}

.status-value {
  font-size: 28px;
  font-weight: 600;
  line-height: 1;
  margin-bottom: 4px;
}

.status-label {
  font-size: 14px;
  color: #909399;
  margin-bottom: 2px;
}

.status-description {
  font-size: 12px;
  color: #C0C4CC;
}

.status-actions {
  margin-left: auto;
}

/* 预设样式 */
.status-icon-primary {
  background-color: #409EFF;
}

.status-icon-success {
  background-color: #67C23A;
}

.status-icon-warning {
  background-color: #E6A23C;
}

.status-icon-danger {
  background-color: #F56C6C;
}

.status-icon-info {
  background-color: #909399;
}
</style>