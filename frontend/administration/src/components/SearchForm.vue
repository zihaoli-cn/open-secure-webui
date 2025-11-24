<template>
  <el-card class="search-form">
    <el-form :model="formModel" :label-width="labelWidth" ref="formRef">
      <el-row :gutter="gutter">
        <!-- 动态表单项 -->
        <slot></slot>

        <!-- 操作按钮 -->
        <el-col :span="24" style="text-align: right">
          <el-button @click="handleReset">
            重置
          </el-button>
          <el-button type="primary" @click="handleSearch">
            查询
          </el-button>
        </el-col>
      </el-row>
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, reactive } from 'vue'

const props = defineProps({
  // 表单配置
  modelValue: {
    type: Object,
    default: () => ({})
  },
  labelWidth: {
    type: String,
    default: '80px'
  },
  gutter: {
    type: Number,
    default: 20
  }
})

const emit = defineEmits(['update:modelValue', 'search', 'reset'])

// 表单引用
const formRef = ref()

// 表单数据
const formModel = reactive({ ...props.modelValue })

// 搜索处理
const handleSearch = () => {
  emit('update:modelValue', { ...formModel })
  emit('search', { ...formModel })
}

// 重置处理
const handleReset = () => {
  Object.keys(formModel).forEach(key => {
    if (Array.isArray(formModel[key])) {
      formModel[key] = []
    } else {
      formModel[key] = ''
    }
  })
  emit('update:modelValue', { ...formModel })
  emit('reset', { ...formModel })
}

// 暴露方法给父组件
defineExpose({
  reset: handleReset,
  search: handleSearch
})
</script>

<style scoped>
.search-form {
  margin-bottom: 16px;
}
</style>