<template>
  <div class="user-management-container">
    <!-- 页面标题和操作栏 -->
    <div class="page-header">
      <div class="header-left">
        <h1 class="page-title">用户管理</h1>
        <p class="page-description">管理系统用户账户和权限</p>
      </div>
      <div class="header-right">
        <el-button type="primary" @click="showCreateDialog = true">
          <el-icon><Plus /></el-icon>
          创建用户
        </el-button>
      </div>
    </div>

    <!-- 搜索和筛选 -->
    <div class="filter-bar">
      <el-row :gutter="20">
        <el-col :span="6">
          <el-input
            v-model="searchQuery"
            placeholder="搜索用户名或邮箱"
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
            <el-option label="非活跃" value="inactive" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-select v-model="filterRole" placeholder="角色筛选" clearable @change="handleFilter">
            <el-option label="全部" value="" />
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
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

    <!-- 用户列表 -->
    <el-card class="table-card">
      <el-table
        :data="users"
        v-loading="loading"
        style="width: 100%"
        empty-text="暂无用户数据"
      >
        <el-table-column prop="username" label="用户名" min-width="120" />
        <el-table-column prop="email" label="邮箱" min-width="150" />
        <el-table-column prop="display_name" label="显示名称" min-width="120" />
        <el-table-column prop="role" label="角色" min-width="100">
          <template #default="{ row }">
            <el-tag :type="getRoleType(row.role)" size="small">
              {{ getRoleText(row.role) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" min-width="80">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">
              {{ getStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_login" label="最后登录" min-width="140">
          <template #default="{ row }">
            {{ formatDate(row.last_login) || '从未登录' }}
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" min-width="140">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="200" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              @click="handleEdit(row)"
            >
              编辑
            </el-button>
            <el-button
              size="small"
              type="warning"
              v-if="row.status === 'active'"
              @click="handleToggleStatus(row)"
            >
              禁用
            </el-button>
            <el-button
              size="small"
              type="success"
              v-if="row.status === 'inactive'"
              @click="handleToggleStatus(row)"
            >
              启用
            </el-button>
            <el-button
              size="small"
              type="danger"
              v-if="!row.is_builtin_admin"
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

    <!-- 创建用户对话框 -->
    <el-dialog
      v-model="showCreateDialog"
      title="创建用户"
      width="500px"
      :before-close="handleCloseCreateDialog"
    >
      <el-form
        ref="createFormRef"
        :model="createForm"
        :rules="createRules"
        label-width="100px"
      >
        <el-form-item label="用户名" prop="username">
          <el-input
            v-model="createForm.username"
            placeholder="请输入用户名"
          />
        </el-form-item>
        <el-form-item label="邮箱" prop="email">
          <el-input
            v-model="createForm.email"
            placeholder="请输入邮箱地址"
          />
        </el-form-item>
        <el-form-item label="显示名称" prop="display_name">
          <el-input
            v-model="createForm.display_name"
            placeholder="请输入显示名称"
          />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="createForm.password"
            type="password"
            placeholder="请输入密码"
            show-password
          />
        </el-form-item>
        <el-form-item label="确认密码" prop="confirmPassword">
          <el-input
            v-model="createForm.confirmPassword"
            type="password"
            placeholder="请再次输入密码"
            show-password
          />
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="createForm.role" placeholder="请选择角色">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
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

    <!-- 编辑用户对话框 -->
    <el-dialog
      v-model="showEditDialog"
      title="编辑用户"
      width="500px"
      :before-close="handleCloseEditDialog"
    >
      <el-form
        ref="editFormRef"
        :model="editForm"
        :rules="editRules"
        label-width="100px"
      >
        <el-form-item label="用户名" prop="username">
          <el-input
            v-model="editForm.username"
            placeholder="请输入用户名"
            :disabled="currentUser?.is_builtin_admin"
          />
        </el-form-item>
        <el-form-item label="邮箱" prop="email">
          <el-input
            v-model="editForm.email"
            placeholder="请输入邮箱地址"
          />
        </el-form-item>
        <el-form-item label="显示名称" prop="display_name">
          <el-input
            v-model="editForm.display_name"
            placeholder="请输入显示名称"
          />
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="editForm.role" placeholder="请选择角色">
            <el-option label="普通用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
        <el-form-item label="状态" prop="status">
          <el-select v-model="editForm.status" placeholder="请选择状态">
            <el-option label="活跃" value="active" />
            <el-option label="非活跃" value="inactive" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="handleCloseEditDialog">取消</el-button>
        <el-button
          type="primary"
          :loading="editLoading"
          @click="handleUpdate"
        >
          保存
        </el-button>
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
const filterRole = ref('')

// 分页
const currentPage = ref(1)
const pageSize = ref(10)
const total = computed(() => sysAdminStore.usersTotal)

// 加载状态
const loading = computed(() => sysAdminStore.usersLoading)

// 用户列表
const users = computed(() => sysAdminStore.users)

// 对话框状态
const showCreateDialog = ref(false)
const showEditDialog = ref(false)
const createLoading = ref(false)
const editLoading = ref(false)

// 当前选中的用户
const currentUser = ref(null)

// 创建表单
const createFormRef = ref()
const createForm = reactive({
  username: '',
  email: '',
  display_name: '',
  password: '',
  confirmPassword: '',
  role: 'user'
})

// 编辑表单
const editFormRef = ref()
const editForm = reactive({
  username: '',
  email: '',
  display_name: '',
  role: '',
  status: ''
})

// 表单验证规则
const createRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 3, max: 20, message: '用户名长度在 3 到 20 个字符', trigger: 'blur' }
  ],
  email: [
    { required: true, message: '请输入邮箱地址', trigger: 'blur' },
    { type: 'email', message: '请输入正确的邮箱地址', trigger: 'blur' }
  ],
  display_name: [
    { required: true, message: '请输入显示名称', trigger: 'blur' }
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码长度不能少于 6 个字符', trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: '请再次输入密码', trigger: 'blur' },
    {
      validator: (rule, value, callback) => {
        if (value !== createForm.password) {
          callback(new Error('两次输入密码不一致'))
        } else {
          callback()
        }
      },
      trigger: 'blur'
    }
  ],
  role: [
    { required: true, message: '请选择角色', trigger: 'change' }
  ]
}

const editRules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' }
  ],
  email: [
    { required: true, message: '请输入邮箱地址', trigger: 'blur' },
    { type: 'email', message: '请输入正确的邮箱地址', trigger: 'blur' }
  ],
  display_name: [
    { required: true, message: '请输入显示名称', trigger: 'blur' }
  ],
  role: [
    { required: true, message: '请选择角色', trigger: 'change' }
  ],
  status: [
    { required: true, message: '请选择状态', trigger: 'change' }
  ]
}

// 获取角色类型
const getRoleType = (role) => {
  return role === 'admin' ? 'danger' : 'primary'
}

// 获取角色文本
const getRoleText = (role) => {
  return role === 'admin' ? '管理员' : '普通用户'
}

// 获取状态类型
const getStatusType = (status) => {
  return status === 'active' ? 'success' : 'warning'
}

// 获取状态文本
const getStatusText = (status) => {
  return status === 'active' ? '活跃' : '非活跃'
}

// 格式化日期
const formatDate = (date) => {
  if (!date) return ''
  return new Date(date).toLocaleString('zh-CN')
}

// 搜索
const handleSearch = () => {
  currentPage.value = 1
  loadUsers()
}

// 筛选
const handleFilter = () => {
  currentPage.value = 1
  loadUsers()
}

// 分页大小改变
const handleSizeChange = (size) => {
  pageSize.value = size
  currentPage.value = 1
  loadUsers()
}

// 当前页改变
const handleCurrentChange = (page) => {
  currentPage.value = page
  loadUsers()
}

// 编辑用户
const handleEdit = (user) => {
  currentUser.value = user
  Object.assign(editForm, {
    username: user.username,
    email: user.email,
    display_name: user.display_name,
    role: user.role,
    status: user.status
  })
  showEditDialog.value = true
}

// 切换用户状态
const handleToggleStatus = async (user) => {
  try {
    const action = user.status === 'active' ? '禁用' : '启用'
    await ElMessageBox.confirm(`确定要${action}用户 "${user.username}" 吗？`, '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    const newStatus = user.status === 'active' ? 'inactive' : 'active'
    await sysAdminStore.updateUser(user.id, { status: newStatus })
    ElMessage.success(`用户已${action}`)
  } catch (error) {
    // 用户取消
  }
}

// 删除用户
const handleDelete = async (user) => {
  try {
    await ElMessageBox.confirm(`确定要删除用户 "${user.username}" 吗？此操作不可恢复。`, '警告', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'error'
    })

    await sysAdminStore.deleteUser(user.id)
    ElMessage.success('用户已删除')
  } catch (error) {
    // 用户取消
  }
}

// 创建用户
const handleCreate = async () => {
  if (!createFormRef.value) return

  try {
    const valid = await createFormRef.value.validate()
    if (!valid) return

    createLoading.value = true

    const userData = {
      username: createForm.username,
      email: createForm.email,
      display_name: createForm.display_name,
      password: createForm.password,
      role: createForm.role
    }

    await sysAdminStore.createUser(userData)
    ElMessage.success('用户创建成功')
    handleCloseCreateDialog()
  } catch (error) {
    console.error('创建用户失败:', error)
    ElMessage.error('创建用户失败')
  } finally {
    createLoading.value = false
  }
}

// 更新用户
const handleUpdate = async () => {
  if (!editFormRef.value) return

  try {
    const valid = await editFormRef.value.validate()
    if (!valid) return

    editLoading.value = true

    const userData = {
      username: editForm.username,
      email: editForm.email,
      display_name: editForm.display_name,
      role: editForm.role,
      status: editForm.status
    }

    await sysAdminStore.updateUser(currentUser.value.id, userData)
    ElMessage.success('用户信息已更新')
    handleCloseEditDialog()
  } catch (error) {
    console.error('更新用户失败:', error)
    ElMessage.error('更新用户失败')
  } finally {
    editLoading.value = false
  }
}

// 关闭创建对话框
const handleCloseCreateDialog = () => {
  showCreateDialog.value = false
  createFormRef.value?.resetFields()
  Object.assign(createForm, {
    username: '',
    email: '',
    display_name: '',
    password: '',
    confirmPassword: '',
    role: 'user'
  })
}

// 关闭编辑对话框
const handleCloseEditDialog = () => {
  showEditDialog.value = false
  editFormRef.value?.resetFields()
  currentUser.value = null
}

// 加载用户列表
const loadUsers = async () => {
  try {
    const params = {
      search: searchQuery.value,
      status: filterStatus.value,
      role: filterRole.value
    }
    await sysAdminStore.loadUsers(params)
  } catch (error) {
    console.error('加载用户列表失败:', error)
    ElMessage.error('加载用户列表失败')
  }
}

// 初始化
onMounted(async () => {
  await loadUsers()
})
</script>

<style scoped>
.user-management-container {
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

.pagination-container {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
  padding: 16px 0;
}
</style>