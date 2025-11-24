<template>
  <div class="model-management-container">
    <!-- 页面标题和操作栏 -->
    <div class="page-header">
      <div class="header-left">
        <h1 class="page-title">模型管理</h1>
        <p class="page-description">管理系统可用的AI模型</p>
      </div>
      <div class="header-right">
        <el-button type="primary" @click="showCreateDialog = true">
          <el-icon><Plus /></el-icon>
          添加模型
        </el-button>
      </div>
    </div>

    <!-- 搜索和筛选 -->
    <div class="filter-bar">
      <el-row :gutter="20">
        <el-col :span="6">
          <el-input
            v-model="searchQuery"
            placeholder="搜索模型名称或提供商"
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
          <el-select v-model="filterProvider" placeholder="提供商筛选" clearable @change="handleFilter">
            <el-option label="全部" value="" />
            <el-option label="OpenAI" value="openai" />
            <el-option label="Anthropic" value="anthropic" />
            <el-option label="Azure" value="azure" />
            <el-option label="Ollama" value="ollama" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-select v-model="filterStatus" placeholder="状态筛选" clearable @change="handleFilter">
            <el-option label="全部" value="" />
            <el-option label="启用" value="enabled" />
            <el-option label="禁用" value="disabled" />
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

    <!-- 模型列表 -->
    <el-card class="table-card">
      <el-table
        :data="models"
        v-loading="loading"
        style="width: 100%"
        empty-text="暂无模型数据"
      >
        <el-table-column prop="name" label="模型名称" min-width="150" />
        <el-table-column prop="display_name" label="显示名称" min-width="120" />
        <el-table-column prop="provider" label="提供商" min-width="100">
          <template #default="{ row }">
            <el-tag :type="getProviderType(row.provider)" size="small">
              {{ getProviderText(row.provider) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="model_type" label="模型类型" min-width="100">
          <template #default="{ row }">
            <el-tag size="small">
              {{ getModelTypeText(row.model_type) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="context_length" label="上下文长度" min-width="100" />
        <el-table-column prop="max_tokens" label="最大输出" min-width="100" />
        <el-table-column prop="enabled" label="状态" min-width="80">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              @change="handleToggleModel(row)"
            />
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" min-width="140">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="150" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              @click="handleEdit(row)"
            >
              编辑
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

    <!-- 添加模型对话框 -->
    <el-dialog
      v-model="showCreateDialog"
      title="添加模型"
      width="600px"
      :before-close="handleCloseCreateDialog"
    >
      <el-form
        ref="createFormRef"
        :model="createForm"
        :rules="createRules"
        label-width="120px"
      >
        <el-form-item label="模型名称" prop="name">
          <el-input
            v-model="createForm.name"
            placeholder="请输入模型名称（唯一标识）"
          />
        </el-form-item>
        <el-form-item label="显示名称" prop="display_name">
          <el-input
            v-model="createForm.display_name"
            placeholder="请输入显示名称"
          />
        </el-form-item>
        <el-form-item label="提供商" prop="provider">
          <el-select v-model="createForm.provider" placeholder="请选择提供商">
            <el-option label="OpenAI" value="openai" />
            <el-option label="Anthropic" value="anthropic" />
            <el-option label="Azure OpenAI" value="azure" />
            <el-option label="Ollama" value="ollama" />
            <el-option label="其他" value="other" />
          </el-select>
        </el-form-item>
        <el-form-item label="模型类型" prop="model_type">
          <el-select v-model="createForm.model_type" placeholder="请选择模型类型">
            <el-option label="文本生成" value="text" />
            <el-option label="聊天" value="chat" />
            <el-option label="代码生成" value="code" />
            <el-option label="图像生成" value="image" />
            <el-option label="语音" value="audio" />
          </el-select>
        </el-form-item>
        <el-form-item label="API密钥" prop="api_key">
          <el-input
            v-model="createForm.api_key"
            type="password"
            placeholder="请输入API密钥"
            show-password
          />
        </el-form-item>
        <el-form-item label="API端点" prop="api_endpoint">
          <el-input
            v-model="createForm.api_endpoint"
            placeholder="请输入API端点URL"
          />
        </el-form-item>
        <el-form-item label="上下文长度" prop="context_length">
          <el-input-number
            v-model="createForm.context_length"
            :min="1024"
            :max="1000000"
            placeholder="请输入上下文长度"
          />
        </el-form-item>
        <el-form-item label="最大输出" prop="max_tokens">
          <el-input-number
            v-model="createForm.max_tokens"
            :min="1"
            :max="10000"
            placeholder="请输入最大输出token数"
          />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="createForm.description"
            type="textarea"
            :rows="3"
            placeholder="请输入模型描述"
          />
        </el-form-item>
        <el-form-item label="状态" prop="enabled">
          <el-switch v-model="createForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="handleCloseCreateDialog">取消</el-button>
        <el-button
          type="primary"
          :loading="createLoading"
          @click="handleCreate"
        >
          添加
        </el-button>
      </template>
    </el-dialog>

    <!-- 编辑模型对话框 -->
    <el-dialog
      v-model="showEditDialog"
      title="编辑模型"
      width="600px"
      :before-close="handleCloseEditDialog"
    >
      <el-form
        ref="editFormRef"
        :model="editForm"
        :rules="editRules"
        label-width="120px"
      >
        <el-form-item label="模型名称" prop="name">
          <el-input
            v-model="editForm.name"
            placeholder="请输入模型名称"
            disabled
          />
        </el-form-item>
        <el-form-item label="显示名称" prop="display_name">
          <el-input
            v-model="editForm.display_name"
            placeholder="请输入显示名称"
          />
        </el-form-item>
        <el-form-item label="提供商" prop="provider">
          <el-select v-model="editForm.provider" placeholder="请选择提供商" disabled>
            <el-option label="OpenAI" value="openai" />
            <el-option label="Anthropic" value="anthropic" />
            <el-option label="Azure OpenAI" value="azure" />
            <el-option label="Ollama" value="ollama" />
            <el-option label="其他" value="other" />
          </el-select>
        </el-form-item>
        <el-form-item label="模型类型" prop="model_type">
          <el-select v-model="editForm.model_type" placeholder="请选择模型类型">
            <el-option label="文本生成" value="text" />
            <el-option label="聊天" value="chat" />
            <el-option label="代码生成" value="code" />
            <el-option label="图像生成" value="image" />
            <el-option label="语音" value="audio" />
          </el-select>
        </el-form-item>
        <el-form-item label="API密钥" prop="api_key">
          <el-input
            v-model="editForm.api_key"
            type="password"
            placeholder="请输入API密钥"
            show-password
          />
        </el-form-item>
        <el-form-item label="API端点" prop="api_endpoint">
          <el-input
            v-model="editForm.api_endpoint"
            placeholder="请输入API端点URL"
          />
        </el-form-item>
        <el-form-item label="上下文长度" prop="context_length">
          <el-input-number
            v-model="editForm.context_length"
            :min="1024"
            :max="1000000"
            placeholder="请输入上下文长度"
          />
        </el-form-item>
        <el-form-item label="最大输出" prop="max_tokens">
          <el-input-number
            v-model="editForm.max_tokens"
            :min="1"
            :max="10000"
            placeholder="请输入最大输出token数"
          />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="editForm.description"
            type="textarea"
            :rows="3"
            placeholder="请输入模型描述"
          />
        </el-form-item>
        <el-form-item label="状态" prop="enabled">
          <el-switch v-model="editForm.enabled" />
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
const filterProvider = ref('')
const filterStatus = ref('')

// 分页
const currentPage = ref(1)
const pageSize = ref(10)
const total = computed(() => sysAdminStore.modelsTotal)

// 加载状态
const loading = computed(() => sysAdminStore.modelsLoading)

// 模型列表
const models = computed(() => sysAdminStore.models)

// 对话框状态
const showCreateDialog = ref(false)
const showEditDialog = ref(false)
const createLoading = ref(false)
const editLoading = ref(false)

// 当前选中的模型
const currentModel = ref(null)

// 创建表单
const createFormRef = ref()
const createForm = reactive({
  name: '',
  display_name: '',
  provider: '',
  model_type: 'chat',
  api_key: '',
  api_endpoint: '',
  context_length: 4096,
  max_tokens: 2048,
  description: '',
  enabled: true
})

// 编辑表单
const editFormRef = ref()
const editForm = reactive({
  name: '',
  display_name: '',
  provider: '',
  model_type: '',
  api_key: '',
  api_endpoint: '',
  context_length: 4096,
  max_tokens: 2048,
  description: '',
  enabled: true
})

// 表单验证规则
const createRules = {
  name: [
    { required: true, message: '请输入模型名称', trigger: 'blur' },
    { min: 2, max: 50, message: '模型名称长度在 2 到 50 个字符', trigger: 'blur' }
  ],
  display_name: [
    { required: true, message: '请输入显示名称', trigger: 'blur' }
  ],
  provider: [
    { required: true, message: '请选择提供商', trigger: 'change' }
  ],
  model_type: [
    { required: true, message: '请选择模型类型', trigger: 'change' }
  ],
  api_key: [
    { required: true, message: '请输入API密钥', trigger: 'blur' }
  ],
  context_length: [
    { required: true, message: '请输入上下文长度', trigger: 'blur' }
  ],
  max_tokens: [
    { required: true, message: '请输入最大输出token数', trigger: 'blur' }
  ]
}

const editRules = {
  display_name: [
    { required: true, message: '请输入显示名称', trigger: 'blur' }
  ],
  model_type: [
    { required: true, message: '请选择模型类型', trigger: 'change' }
  ],
  context_length: [
    { required: true, message: '请输入上下文长度', trigger: 'blur' }
  ],
  max_tokens: [
    { required: true, message: '请输入最大输出token数', trigger: 'blur' }
  ]
}

// 获取提供商类型
const getProviderType = (provider) => {
  const typeMap = {
    'openai': 'success',
    'anthropic': 'warning',
    'azure': 'primary',
    'ollama': 'info',
    'other': 'default'
  }
  return typeMap[provider] || 'default'
}

// 获取提供商文本
const getProviderText = (provider) => {
  const textMap = {
    'openai': 'OpenAI',
    'anthropic': 'Anthropic',
    'azure': 'Azure',
    'ollama': 'Ollama',
    'other': '其他'
  }
  return textMap[provider] || provider
}

// 获取模型类型文本
const getModelTypeText = (modelType) => {
  const textMap = {
    'text': '文本生成',
    'chat': '聊天',
    'code': '代码生成',
    'image': '图像生成',
    'audio': '语音'
  }
  return textMap[modelType] || modelType
}

// 格式化日期
const formatDate = (date) => {
  if (!date) return ''
  return new Date(date).toLocaleString('zh-CN')
}

// 搜索
const handleSearch = () => {
  currentPage.value = 1
  loadModels()
}

// 筛选
const handleFilter = () => {
  currentPage.value = 1
  loadModels()
}

// 分页大小改变
const handleSizeChange = (size) => {
  pageSize.value = size
  currentPage.value = 1
  loadModels()
}

// 当前页改变
const handleCurrentChange = (page) => {
  currentPage.value = page
  loadModels()
}

// 切换模型状态
const handleToggleModel = async (model) => {
  try {
    const action = model.enabled ? '启用' : '禁用'
    await ElMessageBox.confirm(`确定要${action}模型 "${model.display_name}" 吗？`, '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    await sysAdminStore.updateModel(model.id, { enabled: model.enabled })
    ElMessage.success(`模型已${action}`)
  } catch (error) {
    // 如果用户取消，恢复switch状态
    model.enabled = !model.enabled
  }
}

// 编辑模型
const handleEdit = (model) => {
  currentModel.value = model
  Object.assign(editForm, {
    name: model.name,
    display_name: model.display_name,
    provider: model.provider,
    model_type: model.model_type,
    api_key: model.api_key || '',
    api_endpoint: model.api_endpoint || '',
    context_length: model.context_length,
    max_tokens: model.max_tokens,
    description: model.description || '',
    enabled: model.enabled
  })
  showEditDialog.value = true
}

// 删除模型
const handleDelete = async (model) => {
  try {
    await ElMessageBox.confirm(`确定要删除模型 "${model.display_name}" 吗？此操作不可恢复。`, '警告', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'error'
    })

    await sysAdminStore.deleteModel(model.id)
    ElMessage.success('模型已删除')
  } catch (error) {
    // 用户取消
  }
}

// 添加模型
const handleCreate = async () => {
  if (!createFormRef.value) return

  try {
    const valid = await createFormRef.value.validate()
    if (!valid) return

    createLoading.value = true

    const modelData = {
      name: createForm.name,
      display_name: createForm.display_name,
      provider: createForm.provider,
      model_type: createForm.model_type,
      api_key: createForm.api_key,
      api_endpoint: createForm.api_endpoint,
      context_length: createForm.context_length,
      max_tokens: createForm.max_tokens,
      description: createForm.description,
      enabled: createForm.enabled
    }

    await sysAdminStore.addModel(modelData)
    ElMessage.success('模型添加成功')
    handleCloseCreateDialog()
  } catch (error) {
    console.error('添加模型失败:', error)
    ElMessage.error('添加模型失败')
  } finally {
    createLoading.value = false
  }
}

// 更新模型
const handleUpdate = async () => {
  if (!editFormRef.value) return

  try {
    const valid = await editFormRef.value.validate()
    if (!valid) return

    editLoading.value = true

    const modelData = {
      display_name: editForm.display_name,
      model_type: editForm.model_type,
      api_key: editForm.api_key,
      api_endpoint: editForm.api_endpoint,
      context_length: editForm.context_length,
      max_tokens: editForm.max_tokens,
      description: editForm.description,
      enabled: editForm.enabled
    }

    await sysAdminStore.updateModel(currentModel.value.id, modelData)
    ElMessage.success('模型信息已更新')
    handleCloseEditDialog()
  } catch (error) {
    console.error('更新模型失败:', error)
    ElMessage.error('更新模型失败')
  } finally {
    editLoading.value = false
  }
}

// 关闭创建对话框
const handleCloseCreateDialog = () => {
  showCreateDialog.value = false
  createFormRef.value?.resetFields()
  Object.assign(createForm, {
    name: '',
    display_name: '',
    provider: '',
    model_type: 'chat',
    api_key: '',
    api_endpoint: '',
    context_length: 4096,
    max_tokens: 2048,
    description: '',
    enabled: true
  })
}

// 关闭编辑对话框
const handleCloseEditDialog = () => {
  showEditDialog.value = false
  editFormRef.value?.resetFields()
  currentModel.value = null
}

// 加载模型列表
const loadModels = async () => {
  try {
    const params = {
      search: searchQuery.value,
      provider: filterProvider.value,
      enabled: filterStatus.value === 'enabled' ? true : filterStatus.value === 'disabled' ? false : undefined
    }
    await sysAdminStore.loadModels(params)
  } catch (error) {
    console.error('加载模型列表失败:', error)
    ElMessage.error('加载模型列表失败')
  }
}

// 初始化
onMounted(async () => {
  await loadModels()
})
</script>

<style scoped>
.model-management-container {
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