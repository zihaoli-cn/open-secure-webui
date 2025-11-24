<template>
  <div class="data-table">
    <!-- 表格头部 -->
    <div v-if="showHeader" class="table-header">
      <div class="header-left">
        <slot name="header-left">
          <span class="table-title">{{ title }}</span>
        </slot>
      </div>
      <div class="header-right">
        <slot name="header-right">
          <el-button
            v-if="showRefresh"
            @click="$emit('refresh')"
            :loading="loading"
          >
            <el-icon><Refresh /></el-icon>
            刷新
          </el-button>
        </slot>
      </div>
    </div>

    <!-- 数据表格 -->
    <el-table
      v-loading="loading"
      :data="data"
      :border="border"
      :stripe="stripe"
      :size="size"
      @selection-change="handleSelectionChange"
      @sort-change="handleSortChange"
      style="width: 100%"
    >
      <!-- 选择列 -->
      <el-table-column
        v-if="selectable"
        type="selection"
        width="55"
      />

      <!-- 序号列 -->
      <el-table-column
        v-if="showIndex"
        type="index"
        :label="indexLabel"
        :width="indexWidth"
      />

      <!-- 动态列 -->
      <slot></slot>

      <!-- 空状态 -->
      <template #empty>
        <el-empty :description="emptyText" />
      </template>
    </el-table>

    <!-- 分页 -->
    <div v-if="showPagination" class="pagination-container">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="pageSizes"
        :total="total"
        :layout="paginationLayout"
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { Refresh } from '@element-plus/icons-vue'

const props = defineProps({
  // 数据相关
  data: {
    type: Array,
    default: () => []
  },
  loading: {
    type: Boolean,
    default: false
  },

  // 表格配置
  title: {
    type: String,
    default: ''
  },
  border: {
    type: Boolean,
    default: true
  },
  stripe: {
    type: Boolean,
    default: true
  },
  size: {
    type: String,
    default: 'default'
  },

  // 功能配置
  selectable: {
    type: Boolean,
    default: false
  },
  showIndex: {
    type: Boolean,
    default: false
  },
  showHeader: {
    type: Boolean,
    default: true
  },
  showRefresh: {
    type: Boolean,
    default: true
  },
  showPagination: {
    type: Boolean,
    default: true
  },

  // 分页配置
  total: {
    type: Number,
    default: 0
  },
  page: {
    type: Number,
    default: 1
  },
  pageSize: {
    type: Number,
    default: 10
  },
  pageSizes: {
    type: Array,
    default: () => [10, 20, 50, 100]
  },
  paginationLayout: {
    type: String,
    default: 'total, sizes, prev, pager, next, jumper'
  },

  // 文本配置
  indexLabel: {
    type: String,
    default: '序号'
  },
  indexWidth: {
    type: [String, Number],
    default: 80
  },
  emptyText: {
    type: String,
    default: '暂无数据'
  }
})

const emit = defineEmits([
  'refresh',
  'selection-change',
  'sort-change',
  'size-change',
  'current-change'
])

// 分页数据
const currentPage = computed({
  get: () => props.page,
  set: (value) => emit('current-change', value)
})

// 事件处理
const handleSelectionChange = (selection) => {
  emit('selection-change', selection)
}

const handleSortChange = (sort) => {
  emit('sort-change', sort)
}

const handleSizeChange = (size) => {
  emit('size-change', size)
}

const handleCurrentChange = (page) => {
  emit('current-change', page)
}
</script>

<style scoped>
.data-table {
  width: 100%;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  padding: 0 8px;
}

.table-title {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.pagination-container {
  margin-top: 16px;
  text-align: right;
}
</style>