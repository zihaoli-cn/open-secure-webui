<template>
  <el-dialog
    v-model="dialogVisible"
    :title="title"
    :width="width"
    :before-close="handleBeforeClose"
  >
    <!-- 对话框内容 -->
    <div class="confirm-content">
      <div class="confirm-icon">
        <el-icon :size="iconSize" :color="iconColor">
          <component :is="icon" />
        </el-icon>
      </div>
      <div class="confirm-message">
        {{ message }}
      </div>
    </div>

    <!-- 自定义内容插槽 -->
    <slot></slot>

    <!-- 对话框底部 -->
    <template #footer>
      <div class="confirm-footer">
        <el-button @click="handleCancel">
          {{ cancelText }}
        </el-button>
        <el-button
          :type="confirmType"
          :loading="confirmLoading"
          @click="handleConfirm"
        >
          {{ confirmText }}
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  // 对话框配置
  modelValue: {
    type: Boolean,
    default: false
  },
  title: {
    type: String,
    default: '确认操作'
  },
  message: {
    type: String,
    default: '确定要执行此操作吗？'
  },
  width: {
    type: String,
    default: '400px'
  },

  // 图标配置
  icon: {
    type: String,
    default: 'Warning'
  },
  iconSize: {
    type: Number,
    default: 48
  },
  iconColor: {
    type: String,
    default: '#E6A23C'
  },

  // 按钮配置
  confirmText: {
    type: String,
    default: '确定'
  },
  cancelText: {
    type: String,
    default: '取消'
  },
  confirmType: {
    type: String,
    default: 'primary'
  },
  confirmLoading: {
    type: Boolean,
    default: false
  },

  // 预设类型
  type: {
    type: String,
    default: 'warning',
    validator: (value) => ['info', 'success', 'warning', 'danger'].includes(value)
  }
})

const emit = defineEmits([
  'update:modelValue',
  'confirm',
  'cancel',
  'close'
])

// 对话框可见性
const dialogVisible = computed({
  get: () => props.modelValue,
  set: (value) => emit('update:modelValue', value)
})

// 预设配置
const presetConfigs = {
  info: {
    icon: 'InfoFilled',
    iconColor: '#409EFF',
    confirmType: 'primary'
  },
  success: {
    icon: 'SuccessFilled',
    iconColor: '#67C23A',
    confirmType: 'success'
  },
  warning: {
    icon: 'Warning',
    iconColor: '#E6A23C',
    confirmType: 'warning'
  },
  danger: {
    icon: 'CircleCloseFilled',
    iconColor: '#F56C6C',
    confirmType: 'danger'
  }
}

// 计算图标配置
const iconConfig = computed(() => {
  const config = presetConfigs[props.type] || presetConfigs.warning
  return {
    icon: props.icon || config.icon,
    iconColor: props.iconColor || config.iconColor,
    confirmType: props.confirmType || config.confirmType
  }
})

// 事件处理
const handleConfirm = () => {
  emit('confirm')
}

const handleCancel = () => {
  dialogVisible.value = false
  emit('cancel')
}

const handleBeforeClose = (done) => {
  dialogVisible.value = false
  emit('close')
  done()
}

// 暴露方法给父组件
defineExpose({
  open: () => dialogVisible.value = true,
  close: () => dialogVisible.value = false
})
</script>

<style scoped>
.confirm-content {
  display: flex;
  align-items: center;
  padding: 20px 0;
}

.confirm-icon {
  margin-right: 16px;
  flex-shrink: 0;
}

.confirm-message {
  font-size: 16px;
  line-height: 1.5;
  color: #606266;
}

.confirm-footer {
  text-align: right;
}
</style>