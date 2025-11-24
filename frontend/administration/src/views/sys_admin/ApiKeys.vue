<template>
  <div class="api-keys-container">
    <!-- 页面标题和操作栏 -->
    <div class="page-header">
      <div class="header-left">
        <h1 class="page-title">API密钥管理</h1>
        <p class="page-description">管理用户的API密钥和访问权限</p>
      </div>
      <div class="header-right">
        <el-button type="primary" @click="showCreateDialog = true">
          <el-icon><Plus /></el-icon>
          创建密钥
        </el-button>
      </div>
    </div>

    <!-- 搜索和筛选 -->
    <div class="filter-bar">
      <el-row :gutter="20">
        <el-col :span="6">
          <el-input
            v-model="searchQuery"
            placeholder="搜索用户名或密钥名称"
            clearable
            @clear="handleSearch"
            @keyup.enter="handleSearch"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>
        </el-col>
        <el-col :span="4">
          <el-select v-model="filterStatus" placeholder="状态筛选" clearable @change="handleFilter">
            <el-option label="全部" value="" />
            <el-option label="活跃" value="active" />
            <el-option label="已禁用" value="disabled" />
            <el-option label="已过期" value="expired" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button type="primary" @click="handleSearch">
            <el-icon><Search /></el-icon>
            搜索
          </el-button>
        </el-col>
      </el-row>
    </div>

    <!-- API密钥列表 -->
    <el-card class="table-card">
      <el-table
        :data="apiKeys"
        v-loading="loading"
        style="width: 100%"
        empty-text="暂无API密钥"
      >
        <el-table-column prop="name" label="密钥名称" min-width="120" />
        <el-table-column prop="username" label="用户名" min-width="100" />
        <el-table-column prop="key_prefix" label="密钥前缀" min-width="100">
          <template #default="{ row }">
            <span class="key-prefix">{{ row.key_prefix }}***</span>
          </template>
        </el-table-column>
        <el-table-column prop="permissions" label="权限" min-width="120">
          <template #default="{ row }">
            <el-tag
              v-for="perm in row.permissions"
              :key="perm"
              size="small"
              class="permission-tag"
            >
              {{ perm }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" min-width="140">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间" min-width="140">
          <template #default="{ row }">
            <span :class="{ 'expired': isExpired(row.expires_at) }">
              {{ formatDate(row.expires_at) || '永不过期' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" min-width="80">
          <template #default="{ row }">
            <el-tag
              :type="getStatusType(row.status)"
              size="small"
            >
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="180" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              @click="handleView(row)"
            >
              查看
            </el-button>
            <el-button
              size="small"
              type="warning"
              v-if="row.status === 'active'"
              @click="handleDisable(row)"
            >
              禁用
            </el-button>
            <el-button
              size="small"
              type="success"
              v-if="row.status === 'disabled'"
              @click="handleEnable(row)"
            >
              启用
            </el-button>
            <el-button
              size="small"
              type="danger"
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
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>

    <!-- 创建API密钥对话框 -->
    <el-dialog
      v-model="showCreateDialog"
      title="创建API密钥"
      width="500px"
      :before-close="handleCloseCreateDialog"
    >
      <el-form
        ref="createFormRef"
        :model="createForm"
        :rules="createRules"
        label-width="100px"
      >
        <el-form-item label="密钥名称" prop="name">
          <el-input
            v-model="createForm.name"
            placeholder="请输入密钥名称"
          />
        </el-form-item>
        <el-form-item label="用户名" prop="username">
          <el-select
            v-model="createForm.username"
            placeholder="请选择用户"
            filterable
            style="width: 100%"
          >
            <el-option
              v-for="user in userList"
              :key="user.username"
              :label="user.username"
              :value="user.username"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="权限" prop="permissions">
          <el-checkbox-group v-model="createForm.permissions">
            <el-checkbox label="read">读取</el-checkbox>
            <el-checkbox label="write">写入</el-checkbox>
            <el-checkbox label="admin">管理</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="过期时间" prop="expires_at">
          <el-date-picker
            v-model="createForm.expires_at"
            type="datetime"
            placeholder="选择过期时间"
            :disabled-date="disabledDate"
            style="width: 100%"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="handleCloseCreateDialog">取消</el-button>
        <el-button
          type="primary"
          :loading="createLoading"
          @click="handleCreate"
        >
          创建
        </el-button>
      </template>
    </el-dialog>

    <!-- 查看API密钥对话框 -->
    <el-dialog
      v-model="showViewDialog"
      title="API密钥详情"
      width="500px"
    >
      <div class="key-details">
        <div class="detail-item">
          <label>密钥名称：</label>
          <span>{{ currentKey.name }}</span>
        </div>
        <div class="detail-item">
          <label>用户名：</label>
          <span>{{ currentKey.username }}</span>
        </div>
        <div class="detail-item">
          <label>完整密钥：</label>
          <div class="full-key">
            <code>{{ currentKey.full_key }}</code>
            <el-button
              size="small"
              type="primary"
              @click="copyKey(currentKey.full_key)"
            >
              复制
            </el-button>
          </div>
        </div>
        <div class="detail-item">
          <label>权限：</label>
          <div>
            <el-tag
              v-for="perm in currentKey.permissions"
              :key="perm"
              size="small"
              class="permission-tag"
            >
              {{ perm }}
            </el-tag>
          </div>
        </div>
        <div class="detail-item">
          <label>创建时间：</label>
          <span>{{ formatDate(currentKey.created_at) }}</span>
        </div>
        <div class="detail-item">
          <label>过期时间：</label>
          <span>{{ formatDate(currentKey.expires_at) || '永不过期' }}</span>
        </div>
        <div class="detail-item">
          <label>状态：</label>
          <el-tag :type="getStatusType(currentKey.status)">
            {{ getStatusText(currentKey.status) }}
          </el-tag>
        </div>
      </div>
      <template #footer>
        <el-button @click="showViewDialog = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Search } from '@element-plus/icons-vue'
import { useSysAdminStore } from '@/store/modules/sys_admin'

const sysAdminStore = useSysAdminStore()

// 搜索和筛选
const searchQuery = ref('')
const filterStatus = ref('')

// 分页
const currentPage = ref(1)
const pageSize = ref(10)
const total = computed(() => sysAdminStore.apiKeysTotal)

// 加载状态
const loading = computed(() => sysAdminStore.apiKeysLoading)

// API密钥列表
const apiKeys = computed(() => sysAdminStore.apiKeys)

// 用户列表
const userList = computed(() => sysAdminStore.users)

// 对话框状态
const showCreateDialog = ref(false)
const showViewDialog = ref(false)
const createLoading = ref(false)

// 当前选中的密钥
const currentKey = ref({})

// 创建表单
const createFormRef = ref()
const createForm = reactive({
  name: '',
  username: '',
  permissions: ['read'],
  expires_at: null
})

// 表单验证规则
const createRules = {
  name: [{ required: true, message: '请输入密钥名称', trigger: 'blur' }],
  username: [{ required: true, message: '请选择用户', trigger: 'change' }],
  permissions: [{ required: true, message: '请选择至少一个权限', trigger: 'change' }]
}

// 获取状态类型
const getStatusType = (status) => {
  const typeMap = {
    'active': 'success',
    'disabled': 'warning',
    'expired': 'danger'
  }
  return typeMap[status] || 'info'
}

// 获取状态文本
const getStatusText = (status) => {
  const textMap = {
    'active': '活跃',
    'disabled': '已禁用',
    'expired': '已过期'
  }
  return textMap[status] || '未知'
}

// 检查是否过期
const isExpired = (expiresAt) => {
  if (!expiresAt) return false
  return new Date(expiresAt) < new Date()
}

// 格式化日期
const formatDate = (date) => {
  if (!date) return ''
  return new Date(date).toLocaleString('zh-CN')
}

// 禁用日期（只能选择未来日期）
const disabledDate = (time) => {
  return time.getTime() < Date.now()
}

// 复制密钥
const copyKey = async (key) => {
  try {
    await navigator.clipboard.writeText(key)
    ElMessage.success('密钥已复制到剪贴板')
  } catch (error) {
    ElMessage.error('复制失败')
  }
}

// 搜索
const handleSearch = () => {
  currentPage.value = 1
  loadApiKeys()
}

// 筛选
const handleFilter = () => {
  currentPage.value = 1
  loadApiKeys()
}

// 分页大小改变
const handleSizeChange = (size) => {
  pageSize.value = size
  currentPage.value = 1
  loadApiKeys()
}

// 当前页改变
const handleCurrentChange = (page) => {
  currentPage.value = page
  loadApiKeys()
}

// 查看密钥
const handleView = (key) => {
  currentKey.value = { ...key }
  // 模拟完整密钥（实际应该从API获取）
  currentKey.value.full_key = `${key.key_prefix}sk_${Math.random().toString(36).substr(2, 32)}`
  showViewDialog.value = true
}

// 禁用密钥
const handleDisable = async (key) => {
  try {
    await ElMessageBox.confirm('确定要禁用此API密钥吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    await sysAdminStore.disableApiKey(key.id)
    ElMessage.success('密钥已禁用')
  } catch (error) {
    // 用户取消或API错误
  }
}

// 启用密钥
const handleEnable = async (key) => {
  try {
    await ElMessageBox.confirm('确定要启用此API密钥吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    await sysAdminStore.enableApiKey(key.id)
    ElMessage.success('密钥已启用')
  } catch (error) {
    // 用户取消或API错误
  }
}

// 删除密钥
const handleDelete = async (key) => {
  try {
    await ElMessageBox.confirm('确定要删除此API密钥吗？此操作不可恢复。', '警告', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'error'
    })

    await sysAdminStore.deleteApiKey(key.id)
    ElMessage.success('密钥已删除')
  } catch (error) {
    // 用户取消或API错误
  }
}

// 创建密钥
const handleCreate = async () => {
  if (!createFormRef.value) return

  try {
    const valid = await createFormRef.value.validate()
    if (!valid) return

    createLoading.value = true

    const apiKeyData = {
      name: createForm.name,
      username: createForm.username,
      permissions: createForm.permissions,
      expires_at: createForm.expires_at
    }

    await sysAdminStore.createApiKey(apiKeyData)
    ElMessage.success('API密钥创建成功')
    handleCloseCreateDialog()
  } catch (error) {
    console.error('创建API密钥失败:', error)
    ElMessage.error('创建API密钥失败')
  } finally {
    createLoading.value = false
  }
}

// 关闭创建对话框
const handleCloseCreateDialog = () => {
  showCreateDialog.value = false
  createFormRef.value?.resetFields()
  createForm.permissions = ['read']
  createForm.expires_at = null
}

// 加载API密钥列表
const loadApiKeys = async () => {
  try {
    const params = {
      search: searchQuery.value,
      status: filterStatus.value
    }
    await sysAdminStore.loadApiKeys(params)
  } catch (error) {
    console.error('加载API密钥失败:', error)
    ElMessage.error('加载API密钥失败')
  }
}

// 加载用户列表
const loadUserList = async () => {
  try {
    await sysAdminStore.loadUsers({ size: 100 })
  } catch (error) {
    console.error('加载用户列表失败:', error)
  }
}

// 初始化
onMounted(async () => {
  await Promise.all([
    loadApiKeys(),
    loadUserList()
  ])
})
</script>

<style scoped>
.api-keys-container {
  padding: 20px;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
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

.filter-bar {
  margin-bottom: 16px;
}

.table-card {
  border-radius: 8px;
  border: none;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.key-prefix {
  font-family: 'Courier New', monospace;
  background: #f5f7fa;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 12px;
}

.permission-tag {
  margin-right: 4px;
  margin-bottom: 4px;
}

.expired {
  color: #f56c6c;
}

.pagination-container {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
  padding: 16px 0;
}

.key-details {
  padding: 0 20px;
}

.detail-item {
  display: flex;
  align-items: flex-start;
  margin-bottom: 16px;
}

.detail-item label {
  width: 100px;
  font-weight: 500;
  color: #606266;
  flex-shrink: 0;
}

.detail-item span {
  flex: 1;
  color: #303133;
}

.full-key {
  display: flex;
  align-items: center;
  gap: 8px;
}

.full-key code {
  flex: 1;
  background: #f5f7fa;
  padding: 8px 12px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  word-break: break-all;
}
</style>