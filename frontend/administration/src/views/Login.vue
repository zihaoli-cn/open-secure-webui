<template>
  <div class="login-container">
    <div class="login-box">
      <div class="login-header">
        <h1>三员管理系统</h1>
        <p>请选择角色并登录</p>
      </div>

      <el-form
        ref="loginFormRef"
        :model="loginForm"
        :rules="loginRules"
        class="login-form"
        @submit.prevent="handleLogin"
      >
        <el-form-item prop="role">
          <el-select
            v-model="loginForm.role"
            placeholder="请选择角色"
            size="large"
            style="width: 100%"
          >
            <el-option label="系统管理员" value="sys_admin" />
            <el-option label="安全管理员" value="auth_admin" />
            <el-option label="审计管理员" value="audit_admin" />
          </el-select>
        </el-form-item>

        <el-form-item prop="username">
          <el-input
            v-model="loginForm.username"
            placeholder="用户名"
            size="large"
            :prefix-icon="User"
          />
        </el-form-item>

        <el-form-item prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            placeholder="密码"
            size="large"
            :prefix-icon="Lock"
            show-password
            @keyup.enter="handleLogin"
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            size="large"
            style="width: 100%"
            :loading="loading"
            @click="handleLogin"
          >
            登录
          </el-button>
        </el-form-item>
      </el-form>

      <div class="login-footer">
        <el-link type="primary" @click="showChangePassword = true">
          修改密码
        </el-link>
      </div>
    </div>

    <!-- 修改密码对话框 -->
    <el-dialog
      v-model="showChangePassword"
      title="修改密码"
      width="400px"
      :before-close="handleCloseDialog"
    >
      <el-form
        ref="changePasswordFormRef"
        :model="changePasswordForm"
        :rules="changePasswordRules"
        label-width="100px"
      >
        <el-form-item label="用户名" prop="username">
          <el-input v-model="changePasswordForm.username" />
        </el-form-item>
        <el-form-item label="当前密码" prop="currentPassword">
          <el-input
            v-model="changePasswordForm.currentPassword"
            type="password"
            show-password
          />
        </el-form-item>
        <el-form-item label="新密码" prop="newPassword">
          <el-input
            v-model="changePasswordForm.newPassword"
            type="password"
            show-password
          />
        </el-form-item>
        <el-form-item label="确认密码" prop="confirmPassword">
          <el-input
            v-model="changePasswordForm.confirmPassword"
            type="password"
            show-password
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="handleCloseDialog">取消</el-button>
        <el-button
          type="primary"
          :loading="changePasswordLoading"
          @click="handleChangePassword"
        >
          确认修改
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { useAuthStore } from '@/store/modules/auth'

const router = useRouter()
const authStore = useAuthStore()

// 登录表单
const loginFormRef = ref()
const loginForm = reactive({
  role: '',
  username: '',
  password: ''
})

const loginRules = {
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

// 修改密码表单
const changePasswordFormRef = ref()
const showChangePassword = ref(false)
const changePasswordForm = reactive({
  username: '',
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})

const validateConfirmPassword = (rule, value, callback) => {
  if (value !== changePasswordForm.newPassword) {
    callback(new Error('两次输入的密码不一致'))
  } else {
    callback()
  }
}

const changePasswordRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  currentPassword: [{ required: true, message: '请输入当前密码', trigger: 'blur' }],
  newPassword: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, message: '密码长度至少8位', trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: '请确认密码', trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' }
  ]
}

// 加载状态
const loading = ref(false)
const changePasswordLoading = ref(false)

// 根据角色计算用户名提示
const usernamePlaceholder = computed(() => {
  const roleMap = {
    sys_admin: 'sys_admin',
    auth_admin: 'auth_admin',
    audit_admin: 'audit_admin'
  }
  return roleMap[loginForm.role] || '用户名'
})

// 处理登录
const handleLogin = async () => {
  if (!loginFormRef.value) return

  try {
    const valid = await loginFormRef.value.validate()
    if (!valid) return

    loading.value = true

    const credentials = {
      username: loginForm.username,
      password: loginForm.password
    }

    const result = await authStore.login(credentials)

    if (result.success) {
      ElMessage.success('登录成功')
      router.push('/dashboard')
    } else {
      if (result.error === 'password_expired') {
        ElMessage.warning(result.message)
        showChangePassword.value = true
        changePasswordForm.username = loginForm.username
      } else {
        ElMessage.error(result.message || '登录失败')
      }
    }
  } catch (error) {
    console.error('登录错误:', error)
    ElMessage.error('登录失败，请检查网络连接')
  } finally {
    loading.value = false
  }
}

// 处理修改密码
const handleChangePassword = async () => {
  if (!changePasswordFormRef.value) return

  try {
    const valid = await changePasswordFormRef.value.validate()
    if (!valid) return

    changePasswordLoading.value = true

    const result = await authStore.changePassword({
      current_password: changePasswordForm.currentPassword,
      new_password: changePasswordForm.newPassword
    })

    if (result.success) {
      ElMessage.success(result.message)
      handleCloseDialog()
    } else {
      ElMessage.error(result.message)
    }
  } catch (error) {
    console.error('修改密码错误:', error)
    ElMessage.error('修改密码失败')
  } finally {
    changePasswordLoading.value = false
  }
}

// 关闭对话框
const handleCloseDialog = () => {
  showChangePassword.value = false
  changePasswordFormRef.value?.resetFields()
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.login-box {
  width: 400px;
  padding: 40px;
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
}

.login-header {
  text-align: center;
  margin-bottom: 30px;
}

.login-header h1 {
  font-size: 24px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 8px;
}

.login-header p {
  color: #909399;
  font-size: 14px;
}

.login-form {
  margin-bottom: 20px;
}

.login-footer {
  text-align: center;
}
</style>