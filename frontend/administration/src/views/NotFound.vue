<template>
  <div class="error-page">
    <div class="error-content">
      <div class="error-icon">
        <el-icon :size="120" color="#909399">
          <QuestionFilled />
        </el-icon>
      </div>
      <h1 class="error-title">404</h1>
      <p class="error-message">页面未找到</p>
      <p class="error-description">
        抱歉，您访问的页面不存在或已被删除
      </p>
      <div class="error-actions">
        <el-button type="primary" @click="goBack">返回上一页</el-button>
        <el-button @click="goHome">返回首页</el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { QuestionFilled } from '@element-plus/icons-vue'

const router = useRouter()

const goBack = () => {
  router.go(-1)
}

const goHome = () => {
  router.push('/')
}
</script>

<style scoped>
.error-page {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: #f5f7fa;
}

.error-content {
  text-align: center;
  padding: 40px;
}

.error-icon {
  margin-bottom: 20px;
}

.error-title {
  font-size: 72px;
  font-weight: 700;
  color: #303133;
  margin: 0 0 20px;
}

.error-message {
  font-size: 24px;
  color: #606266;
  margin: 0 0 10px;
}

.error-description {
  font-size: 16px;
  color: #909399;
  margin: 0 0 30px;
}

.error-actions {
  display: flex;
  justify-content: center;
  gap: 15px;
}
</style>
