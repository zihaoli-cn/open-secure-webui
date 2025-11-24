<template>
  <div class="layout-container">
    <!-- 顶部导航栏 -->
    <el-header class="layout-header">
      <div class="header-left">
        <h2 class="header-title">三员管理系统</h2>
      </div>
      <div class="header-right">
        <el-dropdown @command="handleCommand">
          <span class="user-info">
            <el-avatar :size="32" :src="userAvatar" />
            <span class="user-name">{{ authStore.displayName }}</span>
            <el-icon><arrow-down /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="profile">
                <el-icon><user /></el-icon>
                个人信息
              </el-dropdown-item>
              <el-dropdown-item command="changePassword">
                <el-icon><lock /></el-icon>
                修改密码
              </el-dropdown-item>
              <el-dropdown-item divided command="logout">
                <el-icon><switch-button /></el-icon>
                退出登录
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </el-header>

    <!-- 主体布局 -->
    <div class="layout-body">
      <!-- 侧边栏 -->
      <el-aside class="layout-sidebar" :width="sidebarWidth">
        <el-menu
          :default-active="activeMenu"
          :collapse="isCollapse"
          router
          class="sidebar-menu"
          background-color="#304156"
          text-color="#bfcbd9"
          active-text-color="#409EFF"
        >
          <template v-for="route in permissionRoutes" :key="route.path">
            <el-menu-item v-if="!route.children" :index="route.path">
              <el-icon v-if="route.meta.icon">
                <component :is="route.meta.icon" />
              </el-icon>
              <template #title>{{ route.meta.title }}</template>
            </el-menu-item>

            <el-sub-menu v-else :index="route.path">
              <template #title>
                <el-icon v-if="route.meta.icon">
                  <component :is="route.meta.icon" />
                </el-icon>
                <span>{{ route.meta.title }}</span>
              </template>
              <el-menu-item
                v-for="child in route.children"
                :key="child.path"
                :index="child.path"
              >
                <template #title>{{ child.meta.title }}</template>
              </el-menu-item>
            </el-sub-menu>
          </template>
        </el-menu>

        <div class="sidebar-collapse" @click="toggleCollapse">
          <el-icon>
            <expand v-if="isCollapse" />
            <fold v-else />
          </el-icon>
        </div>
      </el-aside>

      <!-- 内容区域 -->
      <el-main class="layout-main">
        <router-view />
      </el-main>
    </div>

    <!-- 修改密码对话框 -->
    <el-dialog
      v-model="showChangePassword"
      title="修改密码"
      width="400px"
    >
      <el-form
        ref="changePasswordFormRef"
        :model="changePasswordForm"
        :rules="changePasswordRules"
        label-width="100px"
      >
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
        <el-button @click="showChangePassword = false">取消</el-button>
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
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  User,
  Lock,
  SwitchButton,
  Expand,
  Fold,
  ArrowDown
} from '@element-plus/icons-vue'
import { useAuthStore } from '@/store/modules/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

// 侧边栏状态
const isCollapse = ref(false)
const sidebarWidth = computed(() => (isCollapse.value ? '64px' : '200px'))

// 修改密码对话框
const showChangePassword = ref(false)
const changePasswordFormRef = ref()
const changePasswordLoading = ref(false)
const changePasswordForm = reactive({
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})

// 验证确认密码
const validateConfirmPassword = (rule, value, callback) => {
  if (value !== changePasswordForm.newPassword) {
    callback(new Error('两次输入的密码不一致'))
  } else {
    callback()
  }
}

const changePasswordRules = {
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

// 计算属性
const activeMenu = computed(() => route.path)
const userAvatar = computed(() => {
  // 这里可以根据用户信息返回头像URL
  return ''
})

// 权限路由
const permissionRoutes = computed(() => {
  const routes = router.getRoutes()
  const rootRoute = routes.find(route => route.path === '/')

  if (!rootRoute || !rootRoute.children) return []

  return rootRoute.children.filter(route => {
    // 过滤掉不需要在侧边栏显示的路由
    if (route.meta.hideInMenu) return false

    // 权限检查
    if (route.meta.role && route.meta.role !== authStore.userRole) {
      return false
    }

    return true
  })
})

// 方法
const toggleCollapse = () => {
  isCollapse.value = !isCollapse.value
}

const handleCommand = async (command) => {
  switch (command) {
    case 'profile':
      // 个人信息
      break
    case 'changePassword':
      showChangePassword.value = true
      break
    case 'logout':
      await handleLogout()
      break
  }
}

const handleLogout = async () => {
  try {
    await ElMessageBox.confirm('确定要退出登录吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })

    await authStore.logout()
    ElMessage.success('退出成功')
    router.push('/login')
  } catch (error) {
    // 用户取消
  }
}

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
      showChangePassword.value = false
      changePasswordFormRef.value.resetFields()
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

// 生命周期
onMounted(() => {
  // 检查登录状态
  if (!authStore.isAuthenticated) {
    router.push('/login')
  }
})
</script>

<style scoped>
.layout-container {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.layout-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #fff;
  border-bottom: 1px solid #e6e6e6;
  padding: 0 20px;
  box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
}

.header-title {
  margin: 0;
  color: #303133;
  font-size: 18px;
}

.user-info {
  display: flex;
  align-items: center;
  cursor: pointer;
  padding: 8px 12px;
  border-radius: 4px;
  transition: background-color 0.3s;
}

.user-info:hover {
  background: #f5f7fa;
}

.user-name {
  margin: 0 8px;
  color: #303133;
}

.layout-body {
  display: flex;
  flex: 1;
  overflow: hidden;
}

.layout-sidebar {
  background: #304156;
  position: relative;
  transition: width 0.3s;
}

.sidebar-menu {
  border: none;
  height: calc(100% - 48px);
}

.sidebar-collapse {
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  color: #bfcbd9;
  border-top: 1px solid #2c3a4b;
  transition: background-color 0.3s;
}

.sidebar-collapse:hover {
  background: #263445;
}

.layout-main {
  padding: 20px;
  background: #f0f2f5;
  overflow-y: auto;
}
</style>