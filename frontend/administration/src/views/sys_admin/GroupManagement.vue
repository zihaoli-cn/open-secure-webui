<template>
  <div class="group-management-container">
    <!-- 页面标题和操作栏 -->
    <div class="page-header">
      <div class="header-left">
        <h1 class="page-title">用户组管理</h1>
        <p class="page-description">管理系统用户组和权限分配</p>
      </div>
      <div class="header-right">
        <el-button type="primary" @click="showCreateDialog = true">
          <el-icon><Plus /></el-icon>
          创建用户组
        </el-button>
      </div>
    </div>

    <!-- 搜索和筛选 -->
    <div class="filter-bar">
      <el-row :gutter="20">
        <el-col :span="6">
          <el-input
            v-model="searchQuery"
            placeholder="搜索用户组名称"
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
          <el-button type="primary" @click="handleSearch">
            <el-icon><Search /></el-icon>
            搜索
          </el-button>
        </el-col>
      </el-row>
    </div>

    <!-- 用户组列表 -->
    <el-card class="table-card">
      <el-table
        :data="groups"
        v-loading="loading"
        style="width: 100%"
        empty-text="暂无用户组数据"
      >
        <el-table-column prop="name" label="用户组名称" min-width="120" />
        <el-table-column prop="display_name" label="显示名称" min-width="120" />
        <el-table-column prop="description" label="描述" min-width="150" show-overflow-tooltip />
        <el-table-column prop="user_count" label="成员数量" min-width="80">
          <template #default="{ row }">
            <el-tag size="small">
              {{ row.user_count || 0 }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="permissions" label="权限" min-width="120">
          <template #default="{ row }">
            <div class="permissions-list">
              <el-tag
                v-for="perm in row.permissions"
                :key="perm"
                size="small"
                class="permission-tag"
              >
                {{ getPermissionText(perm) }}
              </el-tag>
            </div>
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
              type="info"
              @click="handleManageMembers(row)"
            >
              管理成员
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

    <!-- 创建用户组对话框 -->
    <el-dialog
      v-model="showCreateDialog"
      title="创建用户组"
      width="500px"
      :before-close="handleCloseCreateDialog"
    >
      <el-form
        ref="createFormRef"
        :model="createForm"
        :rules="createRules"
        label-width="100px"
      >
        <el-form-item label="用户组名称" prop="name">
          <el-input
            v-model="createForm.name"
            placeholder="请输入用户组名称（唯一标识）"
          />
        </el-form-item>
        <el-form-item label="显示名称" prop="display_name">
          <el-input
            v-model="createForm.display_name"
            placeholder="请输入显示名称"
          />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="createForm.description"
            type="textarea"
            :rows="3"
            placeholder="请输入用户组描述"
          />
        </el-form-item>
        <el-form-item label="权限" prop="permissions">
          <el-checkbox-group v-model="createForm.permissions">
            <el-checkbox label="read">读取</el-checkbox>
            <el-checkbox label="write">写入</el-checkbox>
            <el-checkbox label="delete">删除</el-checkbox>
            <el-checkbox label="admin">管理</el-checkbox>
          </el-checkbox-group>
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

    <!-- 编辑用户组对话框 -->
    <el-dialog
      v-model="showEditDialog"
      title="编辑用户组"
      width="500px"
      :before-close="handleCloseEditDialog"
    >
      <el-form
        ref="editFormRef"
        :model="editForm"
        :rules="editRules"
        label-width="100px"
      >
        <el-form-item label="用户组名称" prop="name">
          <el-input
            v-model="editForm.name"
            placeholder="请输入用户组名称"
            disabled
          />
        </el-form-item>
        <el-form-item label="显示名称" prop="display_name">
          <el-input
            v-model="editForm.display_name"
            placeholder="请输入显示名称"
          />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="editForm.description"
            type="textarea"
            :rows="3"
            placeholder="请输入用户组描述"
          />
        </el-form-item>
        <el-form-item label="权限" prop="permissions">
          <el-checkbox-group v-model="editForm.permissions">
            <el-checkbox label="read">读取</el-checkbox>
            <el-checkbox label="write">写入</el-checkbox>
            <el-checkbox label="delete">删除</el-checkbox>
            <el-checkbox label="admin">管理</el-checkbox>
          </el-checkbox-group>
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

    <!-- 管理成员对话框 -->
    <el-dialog
      v-model="showMembersDialog"
      :title="`管理成员 - ${currentGroup?.display_name}`"
      width="700px"
      :before-close="handleCloseMembersDialog"
    >
      <div class="members-management">
        <!-- 添加成员 -->
        <div class="add-member-section">
          <el-select
            v-model="selectedUser"
            placeholder="选择用户添加到组"
            filterable
            style="width: 300px; margin-right: 12px;"
          >
            <el-option
              v-for="user in availableUsers"
              :key="user.id"
              :label="user.username"
              :value="user.id"
              :disabled="isUserInGroup(user.id)"
            >
              <span>{{ user.username }}</span>
              <span style="color: #909399; margin-left: 8px;">({{ user.display_name }})</span>
            </el-option>
          </el-select>
          <el-button
            type="primary"
            :disabled="!selectedUser"
            @click="handleAddMember"
          >
            添加
          </el-button>
        </div>

        <!-- 成员列表 -->
        <div class="members-list">
          <h4>当前成员 ({{ groupMembers.length }})</h4>
          <el-table
            :data="groupMembers"
            style="width: 100%"
            empty-text="暂无成员"
          >
            <el-table-column prop="username" label="用户名" min-width="120" />
            <el-table-column prop="display_name" label="显示名称" min-width="120" />
            <el-table-column prop="email" label="邮箱" min-width="150" />
            <el-table-column label="操作" min-width="80" fixed="right">
              <template #default="{ row }">
                <el-button
                  size="small"
                  type="danger"
                  @click="handleRemoveMember(row)"
                >
                  移除
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
      <template #footer>
        <el-button @click="handleCloseMembersDialog">关闭</el-button>
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

// 分页
const currentPage = ref(1)
const pageSize = ref(10)
const total = computed(() => sysAdminStore.groupsTotal)

// 加载状态
const loading = computed(() => sysAdminStore.groupsLoading)

// 用户组列表
const groups = computed(() => sysAdminStore.groups)

// 对话框状态
const showCreateDialog = ref(false)
const showEditDialog = ref(false)
const showMembersDialog = ref(false)
const createLoading = ref(false)
const editLoading = ref(false)

// 当前选中的用户组
const currentGroup = ref(null)

// 成员管理相关
const selectedUser = ref('')
const groupMembers = ref([])
const availableUsers = ref([])

// 创建表单
const createFormRef = ref()
const createForm = reactive({
  name: '',
  display_name: '',
  description: '',
  permissions: ['read']
})

// 编辑表单
const editFormRef = ref()
const editForm = reactive({
  name: '',
  display_name: '',
  description: '',
  permissions: []
})

// 表单验证规则
const createRules = {
  name: [
    { required: true, message: '请输入用户组名称', trigger: 'blur' },
    { min: 2, max: 50, message: '用户组名称长度在 2 到 50 个字符', trigger: 'blur' }
  ],
  display_name: [
    { required: true, message: '请输入显示名称', trigger: 'blur' }
  ],
  permissions: [
    { required: true, message: '请选择至少一个权限', trigger: 'change' }
  ]
}

const editRules = {
  display_name: [
    { required: true, message: '请输入显示名称', trigger: 'blur' }
  ],
  permissions: [
    { required: true, message: '请选择至少一个权限', trigger: 'change' }
  ]
}

// 获取权限文本
const getPermissionText = (permission) => {
  const textMap = {
    'read': '读取',
    'write': '写入',
    'delete': '删除',
    'admin': '管理'
  }
  return textMap[permission] || permission
}

// 格式化日期
const formatDate = (date) => {
  if (!date) return ''
  return new Date(date).toLocaleString('zh-CN')
}

// 检查用户是否已在组中
const isUserInGroup = (userId) => {
  return groupMembers.value.some(member => member.id === userId)
}

// 搜索
const handleSearch = () => {
  currentPage.value = 1
  loadGroups()
}

// 分页大小改变
const handleSizeChange = (size) => {
  pageSize.value = size
  currentPage.value = 1
  loadGroups()
}

// 当前页改变
const handleCurrentChange = (page) => {
  currentPage.value = page
  loadGroups()
}

// 编辑用户组
const handleEdit = (group) => {
  currentGroup.value = group
  Object.assign(editForm, {
    name: group.name,
    display_name: group.display_name,
    description: group.description || '',
    permissions: group.permissions || []
  })
  showEditDialog.value = true
}

// 管理成员
const handleManageMembers = async (group) => {
  currentGroup.value = group
  try {
    // 加载可用用户列表
    await sysAdminStore.loadUsers({ size: 1000 })
    availableUsers.value = sysAdminStore.users

    // 加载组内成员
    // 这里应该调用API获取组内成员，暂时使用模拟数据
    groupMembers.value = availableUsers.value.slice(0, 3)

    showMembersDialog.value = true
  } catch (error) {
    console.error('加载成员数据失败:', error)
    ElMessage.error('加载成员数据失败')
  }
}

// 删除用户组
const handleDelete = async (group) => {
  try {
    await ElMessageBox.confirm(`确定要删除用户组 "${group.display_name}" 吗？此操作不可恢复。`, '警告', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'error'
    })

    await sysAdminStore.deleteGroup(group.id)
    ElMessage.success('用户组已删除')
  } catch (error) {
    // 用户取消
  }
}

// 创建用户组
const handleCreate = async () => {
  if (!createFormRef.value) return

  try {
    const valid = await createFormRef.value.validate()
    if (!valid) return

    createLoading.value = true

    const groupData = {
      name: createForm.name,
      display_name: createForm.display_name,
      description: createForm.description,
      permissions: createForm.permissions
    }

    await sysAdminStore.createGroup(groupData)
    ElMessage.success('用户组创建成功')
    handleCloseCreateDialog()
  } catch (error) {
    console.error('创建用户组失败:', error)
    ElMessage.error('创建用户组失败')
  } finally {
    createLoading.value = false
  }
}

// 更新用户组
const handleUpdate = async () => {
  if (!editFormRef.value) return

  try {
    const valid = await editFormRef.value.validate()
    if (!valid) return

    editLoading.value = true

    const groupData = {
      display_name: editForm.display_name,
      description: editForm.description,
      permissions: editForm.permissions
    }

    await sysAdminStore.updateGroup(currentGroup.value.id, groupData)
    ElMessage.success('用户组信息已更新')
    handleCloseEditDialog()
  } catch (error) {
    console.error('更新用户组失败:', error)
    ElMessage.error('更新用户组失败')
  } finally {
    editLoading.value = false
  }
}

// 添加成员
const handleAddMember = async () => {
  if (!selectedUser.value) return

  try {
    // 这里应该调用API添加成员
    const user = availableUsers.value.find(u => u.id === selectedUser.value)
    if (user && !isUserInGroup(user.id)) {
      groupMembers.value.push(user)
      ElMessage.success('成员添加成功')
      selectedUser.value = ''
    }
  } catch (error) {
    console.error('添加成员失败:', error)
    ElMessage.error('添加成员失败')
  }
}

// 移除成员
const handleRemoveMember = async (member) => {
  try {
    await ElMessageBox.confirm(`确定要从组中移除用户 "${member.username}" 吗？`, '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    // 这里应该调用API移除成员
    groupMembers.value = groupMembers.value.filter(m => m.id !== member.id)
    ElMessage.success('成员已移除')
  } catch (error) {
    // 用户取消
  }
}

// 关闭创建对话框
const handleCloseCreateDialog = () => {
  showCreateDialog.value = false
  createFormRef.value?.resetFields()
  Object.assign(createForm, {
    name: '',
    display_name: '',
    description: '',
    permissions: ['read']
  })
}

// 关闭编辑对话框
const handleCloseEditDialog = () => {
  showEditDialog.value = false
  editFormRef.value?.resetFields()
  currentGroup.value = null
}

// 关闭成员管理对话框
const handleCloseMembersDialog = () => {
  showMembersDialog.value = false
  selectedUser.value = ''
  groupMembers.value = []
  currentGroup.value = null
}

// 加载用户组列表
const loadGroups = async () => {
  try {
    const params = {
      search: searchQuery.value
    }
    await sysAdminStore.loadGroups(params)
  } catch (error) {
    console.error('加载用户组列表失败:', error)
    ElMessage.error('加载用户组列表失败')
  }
}

// 初始化
onMounted(async () => {
  await loadGroups()
})
</script>

<style scoped>
.group-management-container {
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

.permissions-list {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.permission-tag {
  margin: 2px;
}

.pagination-container {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
  padding: 16px 0;
}

.members-management {
  padding: 0 20px;
}

.add-member-section {
  display: flex;
  align-items: center;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid #f0f0f0;
}

.members-list h4 {
  margin: 0 0 16px 0;
  color: #303133;
  font-weight: 500;
}
</style>