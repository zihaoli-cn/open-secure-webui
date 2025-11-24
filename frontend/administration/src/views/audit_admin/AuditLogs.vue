<template>
  <div class="audit-logs">
    <!-- 页面头部 -->
    <div class="page-header">
      <h1 class="page-title">审计日志</h1>
      <div class="page-actions">
        <el-button type="primary" @click="exportLogs">
          <el-icon><Download /></el-icon>
          导出日志
        </el-button>
        <el-button @click="refreshData">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
      </div>
    </div>

    <!-- 搜索表单 -->
    <el-card class="search-card">
      <el-form :model="searchForm" label-width="80px">
        <el-row :gutter="20">
          <el-col :xs="24" :sm="12" :md="8" :lg="6">
            <el-form-item label="时间范围">
              <el-date-picker
                v-model="searchForm.dateRange"
                type="daterange"
                range-separator="至"
                start-placeholder="开始日期"
                end-placeholder="结束日期"
                value-format="YYYY-MM-DD"
                style="width: 100%"
              />
            </el-form-item>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="6">
            <el-form-item label="操作类型">
              <el-select
                v-model="searchForm.operationType"
                placeholder="请选择操作类型"
                clearable
                style="width: 100%"
              >
                <el-option label="登录" value="login" />
                <el-option label="登出" value="logout" />
                <el-option label="创建" value="create" />
                <el-option label="更新" value="update" />
                <el-option label="删除" value="delete" />
                <el-option label="读取" value="read" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="6">
            <el-form-item label="用户名">
              <el-input
                v-model="searchForm.username"
                placeholder="请输入用户名"
                clearable
              />
            </el-form-item>
          </el-col>
          <el-col :xs="24" :sm="12" :md="8" :lg="6">
            <el-form-item label="状态">
              <el-select
                v-model="searchForm.status"
                placeholder="请选择状态"
                clearable
                style="width: 100%"
              >
                <el-option label="成功" value="success" />
                <el-option label="失败" value="failed" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>
        <el-row>
          <el-col :span="24" style="text-align: right">
            <el-button @click="resetSearch">重置</el-button>
            <el-button type="primary" @click="handleSearch">查询</el-button>
          </el-col>
        </el-row>
      </el-form>
    </el-card>

    <!-- 数据表格 -->
    <el-card>
      <template #header>
        <div class="table-header">
          <span>审计日志列表</span>
          <div class="table-actions">
            <el-button
              type="danger"
              :disabled="selectedLogs.length === 0"
              @click="handleBatchDelete"
            >
              批量删除
            </el-button>
          </div>
        </div>
      </template>

      <el-table
        v-loading="auditLogsLoading"
        :data="auditLogs"
        @selection-change="handleSelectionChange"
        style="width: 100%"
      >
        <el-table-column type="selection" width="55" />
        <el-table-column prop="id" label="ID" width="80" />
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
        <el-table-column prop="description" label="操作描述" min-width="200" />
        <el-table-column prop="ip_address" label="IP地址" width="120" />
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'success' ? 'success' : 'danger'">
              {{ row.status === 'success' ? '成功' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-button
              type="primary"
              link
              @click="viewLogDetail(row)"
            >
              详情
            </el-button>
            <el-button
              type="danger"
              link
              @click="deleteLog(row.id)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination-container">
        <el-pagination
          v-model:current-page="auditLogsPage"
          v-model:page-size="auditLogsPageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="auditLogsTotal"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 日志详情对话框 -->
    <el-dialog
      v-model="detailDialogVisible"
      title="审计日志详情"
      width="600px"
    >
      <el-descriptions :column="1" border v-if="currentLog">
        <el-descriptions-item label="ID">
          {{ currentLog.id }}
        </el-descriptions-item>
        <el-descriptions-item label="时间">
          {{ formatDateTime(currentLog.timestamp) }}
        </el-descriptions-item>
        <el-descriptions-item label="用户">
          {{ currentLog.username }}
        </el-descriptions-item>
        <el-descriptions-item label="操作类型">
          <el-tag :type="getOperationTypeTag(currentLog.operation_type)">
            {{ getOperationTypeLabel(currentLog.operation_type) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="操作描述">
          {{ currentLog.description }}
        </el-descriptions-item>
        <el-descriptions-item label="IP地址">
          {{ currentLog.ip_address }}
        </el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="currentLog.status === 'success' ? 'success' : 'danger'">
            {{ currentLog.status === 'success' ? '成功' : '失败' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="详细信息" v-if="currentLog.details">
          <pre style="white-space: pre-wrap; font-family: inherit;">{{ formatDetails(currentLog.details) }}</pre>
        </el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button @click="detailDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Download, Refresh } from '@element-plus/icons-vue'
import { useAuditAdminStore } from '@/store/modules/audit_admin'

const auditAdminStore = useAuditAdminStore()

// 搜索表单
const searchForm = reactive({
  dateRange: [],
  operationType: '',
  username: '',
  status: ''
})

// 对话框状态
const detailDialogVisible = ref(false)
const currentLog = ref(null)

// 选中的日志
const selectedLogs = ref([])

// 计算属性
const auditLogs = computed(() => auditAdminStore.auditLogs)
const auditLogsLoading = computed(() => auditAdminStore.auditLogsLoading)
const auditLogsTotal = computed(() => auditAdminStore.auditLogsTotal)
const auditLogsPage = computed({
  get: () => auditAdminStore.auditLogsPage,
  set: (value) => auditAdminStore.auditLogsPage = value
})
const auditLogsPageSize = computed({
  get: () => auditAdminStore.auditLogsPageSize,
  set: (value) => auditAdminStore.auditLogsPageSize = value
})

// 初始化数据
const initData = async () => {
  try {
    await auditAdminStore.loadAuditLogs()
  } catch (error) {
    console.error('加载审计日志失败:', error)
    ElMessage.error('加载审计日志失败')
  }
}

// 刷新数据
const refreshData = async () => {
  await initData()
}

// 搜索处理
const handleSearch = async () => {
  const params = {}

  if (searchForm.dateRange && searchForm.dateRange.length === 2) {
    params.start_date = searchForm.dateRange[0]
    params.end_date = searchForm.dateRange[1]
  }

  if (searchForm.operationType) {
    params.operation_type = searchForm.operationType
  }

  if (searchForm.username) {
    params.username = searchForm.username
  }

  if (searchForm.status) {
    params.status = searchForm.status
  }

  try {
    await auditAdminStore.searchAuditLogs(params)
  } catch (error) {
    console.error('搜索审计日志失败:', error)
    ElMessage.error('搜索审计日志失败')
  }
}

// 重置搜索
const resetSearch = () => {
  Object.assign(searchForm, {
    dateRange: [],
    operationType: '',
    username: '',
    status: ''
  })
  initData()
}

// 分页处理
const handleSizeChange = (size) => {
  auditLogsPageSize.value = size
  auditLogsPage.value = 1
  initData()
}

const handleCurrentChange = (page) => {
  auditLogsPage.value = page
  initData()
}

// 选择处理
const handleSelectionChange = (selection) => {
  selectedLogs.value = selection
}

// 查看日志详情
const viewLogDetail = async (log) => {
  try {
    const response = await auditAdminStore.getAuditLogDetail(log.id)
    currentLog.value = response.data || log
    detailDialogVisible.value = true
  } catch (error) {
    console.error('获取日志详情失败:', error)
    ElMessage.error('获取日志详情失败')
  }
}

// 删除日志
const deleteLog = async (logId) => {
  try {
    await ElMessageBox.confirm(
      '确定要删除这条审计日志吗？此操作不可恢复。',
      '确认删除',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    await auditAdminStore.batchDeleteAuditLogs([logId])
    ElMessage.success('删除成功')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('删除日志失败:', error)
      ElMessage.error('删除日志失败')
    }
  }
}

// 批量删除
const handleBatchDelete = async () => {
  if (selectedLogs.value.length === 0) return

  try {
    await ElMessageBox.confirm(
      `确定要删除选中的 ${selectedLogs.value.length} 条审计日志吗？此操作不可恢复。`,
      '确认批量删除',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    const logIds = selectedLogs.value.map(log => log.id)
    await auditAdminStore.batchDeleteAuditLogs(logIds)
    selectedLogs.value = []
    ElMessage.success('批量删除成功')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('批量删除失败:', error)
      ElMessage.error('批量删除失败')
    }
  }
}

// 导出日志
const exportLogs = async () => {
  try {
    const exportParams = {}

    if (searchForm.dateRange && searchForm.dateRange.length === 2) {
      exportParams.start_date = searchForm.dateRange[0]
      exportParams.end_date = searchForm.dateRange[1]
    }

    if (searchForm.operationType) {
      exportParams.operation_type = searchForm.operationType
    }

    if (searchForm.username) {
      exportParams.username = searchForm.username
    }

    if (searchForm.status) {
      exportParams.status = searchForm.status
    }

    await auditAdminStore.exportAuditLogs(exportParams)
    ElMessage.success('导出成功')
  } catch (error) {
    console.error('导出日志失败:', error)
    ElMessage.error('导出日志失败')
  }
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
</script>

<style scoped>
.audit-logs {
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

.search-card {
  margin-bottom: 20px;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.pagination-container {
  margin-top: 20px;
  text-align: right;
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