<template>
  <div class="security-config">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1 class="page-title">安全配置管理</h1>
      <p class="page-description">配置系统全局安全设置和策略</p>
    </div>

    <!-- 配置表单 -->
    <el-card class="config-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span class="card-title">全局安全设置</span>
          <div class="card-actions">
            <el-button
              type="primary"
              :loading="securityConfigLoading"
              @click="saveConfig"
            >
              保存配置
            </el-button>
            <el-button
              @click="resetConfig"
            >
              重置
            </el-button>
          </div>
        </div>
      </template>

      <el-form
        ref="configFormRef"
        :model="configForm"
        :rules="configRules"
        label-width="180px"
        label-position="left"
      >
        <!-- 会话管理配置 -->
        <el-divider content-position="left">会话管理</el-divider>

        <el-form-item label="会话超时时间" prop="session_timeout">
          <el-input-number
            v-model="configForm.session_timeout"
            :min="5"
            :max="1440"
            :step="5"
            controls-position="right"
          />
          <span class="form-unit">分钟</span>
          <div class="form-tip">用户会话自动超时时间，范围：5-1440分钟</div>
        </el-form-item>

        <el-form-item label="最大登录尝试次数" prop="max_login_attempts">
          <el-input-number
            v-model="configForm.max_login_attempts"
            :min="1"
            :max="10"
            controls-position="right"
          />
          <span class="form-unit">次</span>
          <div class="form-tip">连续登录失败后账户将被锁定</div>
        </el-form-item>

        <el-form-item label="账户锁定时间" prop="account_lockout_duration">
          <el-input-number
            v-model="configForm.account_lockout_duration"
            :min="5"
            :max="1440"
            :step="5"
            controls-position="right"
          />
          <span class="form-unit">分钟</span>
          <div class="form-tip">账户被锁定后的持续时间</div>
        </el-form-item>

        <!-- 登录安全配置 -->
        <el-divider content-position="left">登录安全</el-divider>

        <el-form-item label="强制双因素认证" prop="force_2fa">
          <el-switch
            v-model="configForm.force_2fa"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">强制所有用户启用双因素认证</div>
        </el-form-item>

        <el-form-item label="允许记住登录" prop="remember_me_enabled">
          <el-switch
            v-model="configForm.remember_me_enabled"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">允许用户选择"记住我"功能</div>
        </el-form-item>

        <el-form-item label="记住登录时长" prop="remember_me_duration" v-if="configForm.remember_me_enabled">
          <el-input-number
            v-model="configForm.remember_me_duration"
            :min="1"
            :max="30"
            controls-position="right"
          />
          <span class="form-unit">天</span>
          <div class="form-tip">记住登录状态的持续时间</div>
        </el-form-item>

        <!-- 系统安全配置 -->
        <el-divider content-position="left">系统安全</el-divider>

        <el-form-item label="安全等级" prop="security_level">
          <el-select
            v-model="configForm.security_level"
            placeholder="请选择安全等级"
            style="width: 200px"
          >
            <el-option label="低" value="low" />
            <el-option label="中" value="medium" />
            <el-option label="高" value="high" />
            <el-option label="严格" value="critical" />
          </el-select>
          <div class="form-tip">
            <span v-if="configForm.security_level === 'low'">基本安全要求，适合内部测试环境</span>
            <span v-else-if="configForm.security_level === 'medium'">标准安全要求，适合一般生产环境</span>
            <span v-else-if="configForm.security_level === 'high'">增强安全要求，适合敏感数据环境</span>
            <span v-else-if="configForm.security_level === 'critical'">最高安全要求，适合关键业务系统</span>
            <span v-else>请选择合适的安全等级</span>
          </div>
        </el-form-item>

        <el-form-item label="启用审计日志" prop="audit_log_enabled">
          <el-switch
            v-model="configForm.audit_log_enabled"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">记录所有用户操作和系统事件</div>
        </el-form-item>

        <el-form-item label="日志保留天数" prop="log_retention_days" v-if="configForm.audit_log_enabled">
          <el-input-number
            v-model="configForm.log_retention_days"
            :min="7"
            :max="365"
            controls-position="right"
          />
          <span class="form-unit">天</span>
          <div class="form-tip">审计日志的保留时间，范围：7-365天</div>
        </el-form-item>

        <el-form-item label="启用IP白名单" prop="ip_whitelist_enabled">
          <el-switch
            v-model="configForm.ip_whitelist_enabled"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">仅允许白名单中的IP地址访问系统</div>
        </el-form-item>

        <!-- 高级安全配置 -->
        <el-divider content-position="left">高级安全</el-divider>

        <el-form-item label="启用API速率限制" prop="api_rate_limit_enabled">
          <el-switch
            v-model="configForm.api_rate_limit_enabled"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">限制API调用的频率以防止滥用</div>
        </el-form-item>

        <el-form-item label="API请求限制" prop="api_rate_limit" v-if="configForm.api_rate_limit_enabled">
          <el-input-number
            v-model="configForm.api_rate_limit"
            :min="10"
            :max="1000"
            :step="10"
            controls-position="right"
          />
          <span class="form-unit">次/分钟</span>
          <div class="form-tip">每分钟允许的最大API请求次数</div>
        </el-form-item>

        <el-form-item label="启用文件上传扫描" prop="file_upload_scan_enabled">
          <el-switch
            v-model="configForm.file_upload_scan_enabled"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">扫描上传的文件以检测恶意内容</div>
        </el-form-item>

        <el-form-item label="最大文件上传大小" prop="max_file_size">
          <el-input-number
            v-model="configForm.max_file_size"
            :min="1"
            :max="100"
            controls-position="right"
          />
          <span class="form-unit">MB</span>
          <div class="form-tip">单个文件的最大上传大小</div>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 配置预览 -->
    <el-card class="preview-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span class="card-title">配置预览</span>
        </div>
      </template>
      <div class="preview-content">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="会话超时">
            {{ configForm.session_timeout }} 分钟
          </el-descriptions-item>
          <el-descriptions-item label="登录尝试限制">
            {{ configForm.max_login_attempts }} 次
          </el-descriptions-item>
          <el-descriptions-item label="安全等级">
            <el-tag :type="getSecurityLevelType(configForm.security_level)">
              {{ getSecurityLevelText(configForm.security_level) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="双因素认证">
            <el-tag :type="configForm.force_2fa ? 'success' : 'info'">
              {{ configForm.force_2fa ? '强制启用' : '可选' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="审计日志">
            <el-tag :type="configForm.audit_log_enabled ? 'success' : 'info'">
              {{ configForm.audit_log_enabled ? '已启用' : '已禁用' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="IP白名单">
            <el-tag :type="configForm.ip_whitelist_enabled ? 'success' : 'info'">
              {{ configForm.ip_whitelist_enabled ? '已启用' : '已禁用' }}
            </el-tag>
          </el-descriptions-item>
        </el-descriptions>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthAdminStore } from '@/store/modules/auth_admin'

const authAdminStore = useAuthAdminStore()
const configFormRef = ref()

// 表单数据
const configForm = reactive({
  session_timeout: 30,
  max_login_attempts: 5,
  account_lockout_duration: 30,
  force_2fa: false,
  remember_me_enabled: true,
  remember_me_duration: 7,
  security_level: 'medium',
  audit_log_enabled: true,
  log_retention_days: 90,
  ip_whitelist_enabled: false,
  api_rate_limit_enabled: true,
  api_rate_limit: 100,
  file_upload_scan_enabled: true,
  max_file_size: 10
})

// 表单验证规则
const configRules = {
  session_timeout: [
    { required: true, message: '请输入会话超时时间', trigger: 'blur' }
  ],
  max_login_attempts: [
    { required: true, message: '请输入最大登录尝试次数', trigger: 'blur' }
  ],
  account_lockout_duration: [
    { required: true, message: '请输入账户锁定时间', trigger: 'blur' }
  ],
  security_level: [
    { required: true, message: '请选择安全等级', trigger: 'change' }
  ]
}

// 安全等级文本映射
const getSecurityLevelText = (level) => {
  const levelMap = {
    'low': '低',
    'medium': '中',
    'high': '高',
    'critical': '严格'
  }
  return levelMap[level] || '未知'
}

const getSecurityLevelType = (level) => {
  const typeMap = {
    'low': 'danger',
    'medium': 'warning',
    'high': 'success',
    'critical': 'info'
  }
  return typeMap[level] || 'info'
}

// 保存配置
const saveConfig = async () => {
  try {
    await configFormRef.value.validate()

    await authAdminStore.updateSecurityConfig(configForm)
    ElMessage.success('安全配置保存成功')
  } catch (error) {
    console.error('保存安全配置失败:', error)
    ElMessage.error('保存安全配置失败')
  }
}

// 重置配置
const resetConfig = async () => {
  try {
    await ElMessageBox.confirm(
      '确定要重置所有安全配置为默认值吗？',
      '重置确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    // 重置为默认值
    Object.assign(configForm, {
      session_timeout: 30,
      max_login_attempts: 5,
      account_lockout_duration: 30,
      force_2fa: false,
      remember_me_enabled: true,
      remember_me_duration: 7,
      security_level: 'medium',
      audit_log_enabled: true,
      log_retention_days: 90,
      ip_whitelist_enabled: false,
      api_rate_limit_enabled: true,
      api_rate_limit: 100,
      file_upload_scan_enabled: true,
      max_file_size: 10
    })

    ElMessage.success('安全配置已重置为默认值')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('重置安全配置失败:', error)
      ElMessage.error('重置安全配置失败')
    }
  }
}

// 加载配置
const loadConfig = async () => {
  try {
    const response = await authAdminStore.loadSecurityConfig()
    if (response.data) {
      Object.assign(configForm, response.data)
    }
  } catch (error) {
    console.error('加载安全配置失败:', error)
    ElMessage.error('加载安全配置失败')
  }
}

onMounted(() => {
  loadConfig()
})
</script>

<style scoped>
.security-config {
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

.config-card {
  margin-bottom: 24px;
  border-radius: 8px;
}

.preview-card {
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

.card-actions {
  display: flex;
  gap: 8px;
}

:deep(.el-divider__text) {
  font-size: 14px;
  font-weight: 500;
  color: #303133;
}

:deep(.el-form-item) {
  margin-bottom: 20px;
}

.form-unit {
  margin-left: 8px;
  color: #606266;
  font-size: 14px;
}

.form-tip {
  margin-top: 4px;
  font-size: 12px;
  color: #909399;
  line-height: 1.4;
}

.preview-content {
  padding: 16px 0;
}

:deep(.el-descriptions) {
  margin-top: 8px;
}

:deep(.el-descriptions__label) {
  font-weight: 500;
}
</style>