<template>
  <div class="ip-whitelist">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1 class="page-title">IP白名单管理</h1>
      <p class="page-description">管理允许访问系统的IP地址和范围</p>
    </div>

    <!-- 操作工具栏 -->
    <el-card class="toolbar-card" shadow="never">
      <div class="toolbar">
        <div class="toolbar-left">
          <el-button
            type="primary"
            @click="handleAddIp"
          >
            <el-icon><Plus /></el-icon>
            添加IP地址
          </el-button>
          <el-button
            :disabled="selectedIps.length === 0"
            @click="handleBatchEnable"
          >
            <el-icon><Check /></el-icon>
            批量启用
          </el-button>
          <el-button
            :disabled="selectedIps.length === 0"
            @click="handleBatchDisable"
          >
            <el-icon><Close /></el-icon>
            批量禁用
          </el-button>
          <el-button
            :disabled="selectedIps.length === 0"
            type="danger"
            @click="handleBatchDelete"
          >
            <el-icon><Delete /></el-icon>
            批量删除
          </el-button>
        </div>
        <div class="toolbar-right">
          <el-input
            v-model="searchKeyword"
            placeholder="搜索IP地址或描述"
            style="width: 240px"
            clearable
            @clear="handleSearch"
            @keyup.enter="handleSearch"
          >
            <template #append>
              <el-button @click="handleSearch">
                <el-icon><Search /></el-icon>
              </el-button>
            </template>
          </el-input>
        </div>
      </div>
    </el-card>

    <!-- IP地址列表 -->
    <el-card class="list-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span class="card-title">IP白名单列表</span>
          <div class="card-stats">
            <span class="stat-item">
              总计: {{ ipWhitelistTotal }}
            </span>
            <span class="stat-item">
              活跃: {{ activeIpsCount }}
            </span>
            <span class="stat-item">
              禁用: {{ inactiveIpsCount }}
            </span>
          </div>
        </div>
      </template>

      <el-table
        v-loading="ipWhitelistLoading"
        :data="ipWhitelist"
        @selection-change="handleSelectionChange"
        style="width: 100%"
      >
        <el-table-column type="selection" width="55" />
        <el-table-column prop="ip_address" label="IP地址" min-width="180">
          <template #default="{ row }">
            <div class="ip-address">
              <span class="address-text">{{ row.ip_address }}</span>
              <el-tag
                v-if="row.is_range"
                size="small"
                type="info"
              >
                范围
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag
              :type="row.status === 'active' ? 'success' : 'info'"
              size="small"
            >
              {{ row.status === 'active' ? '活跃' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column prop="updated_at" label="更新时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.updated_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.status === 'active'"
              type="warning"
              size="small"
              @click="handleToggleStatus(row, 'inactive')"
            >
              禁用
            </el-button>
            <el-button
              v-else
              type="success"
              size="small"
              @click="handleToggleStatus(row, 'active')"
            >
              启用
            </el-button>
            <el-button
              type="primary"
              size="small"
              @click="handleEdit(row)"
            >
              编辑
            </el-button>
            <el-button
              type="danger"
              size="small"
              @click="handleDelete(row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination-container">
        <el-pagination
          v-model:current-page="ipWhitelistPage"
          v-model:page-size="ipWhitelistPageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="ipWhitelistTotal"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 添加/编辑IP对话框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="dialogTitle"
      width="500px"
      :before-close="handleDialogClose"
    >
      <el-form
        ref="ipFormRef"
        :model="ipForm"
        :rules="ipRules"
        label-width="100px"
      >
        <el-form-item label="IP地址" prop="ip_address">
          <el-input
            v-model="ipForm.ip_address"
            placeholder="请输入IP地址或范围 (如: 192.168.1.1 或 192.168.1.0/24)"
            @blur="validateIpAddress"
          />
          <div class="form-tip">支持单个IP地址或CIDR格式的IP范围</div>
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="ipForm.description"
            type="textarea"
            :rows="3"
            placeholder="请输入IP地址的描述信息"
            maxlength="200"
            show-word-limit
          />
        </el-form-item>
        <el-form-item label="状态" prop="status">
          <el-radio-group v-model="ipForm.status">
            <el-radio label="active">活跃</el-radio>
            <el-radio label="inactive">禁用</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="handleDialogClose">取消</el-button>
          <el-button type="primary" @click="handleSubmit" :loading="submitting">
            确定
          </el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthAdminStore } from '@/store/modules/auth_admin'
import {
  Plus,
  Check,
  Close,
  Delete,
  Search
} from '@element-plus/icons-vue'

const authAdminStore = useAuthAdminStore()
const ipFormRef = ref()

// 搜索关键词
const searchKeyword = ref('')

// 选中的IP地址
const selectedIps = ref([])

// 对话框状态
const dialogVisible = ref(false)
const dialogTitle = ref('')
const submitting = ref(false)

// 表单数据
const ipForm = reactive({
  id: null,
  ip_address: '',
  description: '',
  status: 'active'
})

// 表单验证规则
const ipRules = {
  ip_address: [
    { required: true, message: '请输入IP地址', trigger: 'blur' },
    { validator: validateIpFormat, trigger: 'blur' }
  ],
  description: [
    { required: true, message: '请输入描述信息', trigger: 'blur' },
    { min: 2, max: 200, message: '描述长度在 2 到 200 个字符', trigger: 'blur' }
  ],
  status: [
    { required: true, message: '请选择状态', trigger: 'change' }
  ]
}

// 计算属性
const ipWhitelist = computed(() => authAdminStore.ipWhitelist)
const ipWhitelistLoading = computed(() => authAdminStore.ipWhitelistLoading)
const ipWhitelistTotal = computed(() => authAdminStore.ipWhitelistTotal)
const ipWhitelistPage = computed({
  get: () => authAdminStore.ipWhitelistPage,
  set: (value) => { authAdminStore.ipWhitelistPage = value }
})
const ipWhitelistPageSize = computed({
  get: () => authAdminStore.ipWhitelistPageSize,
  set: (value) => { authAdminStore.ipWhitelistPageSize = value }
})

const activeIpsCount = computed(() => {
  return ipWhitelist.value.filter(ip => ip.status === 'active').length
})

const inactiveIpsCount = computed(() => {
  return ipWhitelist.value.filter(ip => ip.status === 'inactive').length
})

// IP地址格式验证
const validateIpFormat = (rule, value, callback) => {
  if (!value) {
    callback(new Error('请输入IP地址'))
    return
  }

  // 单个IP地址验证
  const singleIpRegex = /^(\d{1,3}\.){3}\d{1,3}$/
  // CIDR格式验证
  const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$

  if (singleIpRegex.test(value) || cidrRegex.test(value)) {
    callback()
  } else {
    callback(new Error('请输入有效的IP地址或CIDR格式的IP范围'))
  }
}

// 验证IP地址
const validateIpAddress = async () => {
  if (!ipForm.ip_address) return

  try {
    await authAdminStore.validateIpFormat(ipForm.ip_address)
  } catch (error) {
    console.error('IP地址验证失败:', error)
  }
}

// 格式化时间
const formatTime = (time) => {
  if (!time) return '--'
  const date = new Date(time)
  return date.toLocaleString('zh-CN')
}

// 表格选择变化
const handleSelectionChange = (selection) => {
  selectedIps.value = selection
}

// 分页大小变化
const handleSizeChange = (size) => {
  ipWhitelistPageSize.value = size
  loadIpWhitelist()
}

// 当前页变化
const handleCurrentChange = (page) => {
  ipWhitelistPage.value = page
  loadIpWhitelist()
}

// 搜索
const handleSearch = () => {
  ipWhitelistPage.value = 1
  loadIpWhitelist()
}

// 添加IP地址
const handleAddIp = () => {
  dialogTitle.value = '添加IP地址'
  resetForm()
  dialogVisible.value = true
}

// 编辑IP地址
const handleEdit = (row) => {
  dialogTitle.value = '编辑IP地址'
  Object.assign(ipForm, {
    id: row.id,
    ip_address: row.ip_address,
    description: row.description,
    status: row.status
  })
  dialogVisible.value = true
}

// 切换状态
const handleToggleStatus = async (row, status) => {
  try {
    if (status === 'active') {
      await authAdminStore.enableIpAddress(row.id)
      ElMessage.success('IP地址已启用')
    } else {
      await authAdminStore.disableIpAddress(row.id)
      ElMessage.success('IP地址已禁用')
    }
  } catch (error) {
    console.error('切换IP状态失败:', error)
    ElMessage.error('操作失败')
  }
}

// 删除IP地址
const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确定要删除IP地址 "${row.ip_address}" 吗？`,
      '删除确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    await authAdminStore.deleteIpAddress(row.id)
    ElMessage.success('IP地址删除成功')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('删除IP地址失败:', error)
      ElMessage.error('删除失败')
    }
  }
}

// 批量启用
const handleBatchEnable = async () => {
  try {
    const ipIds = selectedIps.value.map(ip => ip.id)
    await authAdminStore.batchToggleIpAddresses(ipIds, true)
    ElMessage.success('批量启用成功')
    selectedIps.value = []
  } catch (error) {
    console.error('批量启用失败:', error)
    ElMessage.error('批量启用失败')
  }
}

// 批量禁用
const handleBatchDisable = async () => {
  try {
    const ipIds = selectedIps.value.map(ip => ip.id)
    await authAdminStore.batchToggleIpAddresses(ipIds, false)
    ElMessage.success('批量禁用成功')
    selectedIps.value = []
  } catch (error) {
    console.error('批量禁用失败:', error)
    ElMessage.error('批量禁用失败')
  }
}

// 批量删除
const handleBatchDelete = async () => {
  try {
    const ipAddresses = selectedIps.value.map(ip => ip.ip_address).join(', ')
    await ElMessageBox.confirm(
      `确定要删除选中的 ${selectedIps.value.length} 个IP地址吗？\n${ipAddresses}`,
      '批量删除确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    // 逐个删除选中的IP地址
    for (const ip of selectedIps.value) {
      await authAdminStore.deleteIpAddress(ip.id)
    }

    ElMessage.success('批量删除成功')
    selectedIps.value = []
  } catch (error) {
    if (error !== 'cancel') {
      console.error('批量删除失败:', error)
      ElMessage.error('批量删除失败')
    }
  }
}

// 对话框关闭
const handleDialogClose = () => {
  dialogVisible.value = false
  resetForm()
}

// 提交表单
const handleSubmit = async () => {
  try {
    await ipFormRef.value.validate()
    submitting.value = true

    if (ipForm.id) {
      // 编辑
      await authAdminStore.updateIpAddress(ipForm.id, ipForm)
      ElMessage.success('IP地址更新成功')
    } else {
      // 添加
      await authAdminStore.addIpAddress(ipForm)
      ElMessage.success('IP地址添加成功')
    }

    dialogVisible.value = false
    resetForm()
  } catch (error) {
    console.error('提交IP地址失败:', error)
    ElMessage.error('操作失败')
  } finally {
    submitting.value = false
  }
}

// 重置表单
const resetForm = () => {
  Object.assign(ipForm, {
    id: null,
    ip_address: '',
    description: '',
    status: 'active'
  })
  if (ipFormRef.value) {
    ipFormRef.value.clearValidate()
  }
}

// 加载IP白名单
const loadIpWhitelist = async () => {
  try {
    const params = {}
    if (searchKeyword.value) {
      params.search = searchKeyword.value
    }
    await authAdminStore.loadIpWhitelist(params)
  } catch (error) {
    console.error('加载IP白名单失败:', error)
    ElMessage.error('加载失败')
  }
}

onMounted(() => {
  loadIpWhitelist()
})
</script>

<style scoped>
.ip-whitelist {
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

.toolbar-card {
  margin-bottom: 16px;
  border-radius: 8px;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.toolbar-left {
  display: flex;
  gap: 8px;
}

.toolbar-right {
  display: flex;
  gap: 8px;
}

.list-card {
  border-radius: 8px;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.card-title {
  font-size: 16px;
  font-weight: 500;
  color: #303133;
}

.card-stats {
  display: flex;
  gap: 16px;
  font-size: 14px;
  color: #606266;
}

.stat-item {
  padding: 4px 8px;
  background: #f5f7fa;
  border-radius: 4px;
}

.ip-address {
  display: flex;
  align-items: center;
  gap: 8px;
}

.address-text {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
}

.pagination-container {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}

.form-tip {
  margin-top: 4px;
  font-size: 12px;
  color: #909399;
  line-height: 1.4;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
</style>