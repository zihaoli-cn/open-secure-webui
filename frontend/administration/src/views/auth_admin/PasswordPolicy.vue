<template>
  <div class="password-policy">
    <!-- 页面标题 -->
    <div class="page-header">
      <h1 class="page-title">密码策略管理</h1>
      <p class="page-description">配置用户密码复杂度要求和安全策略</p>
    </div>

    <!-- 策略配置表单 -->
    <el-card class="policy-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span class="card-title">密码策略配置</span>
          <div class="card-actions">
            <el-button
              type="primary"
              :loading="passwordPolicyLoading"
              @click="savePolicy"
            >
              保存策略
            </el-button>
            <el-button
              @click="resetPolicy"
            >
              重置为默认值
            </el-button>
            <el-button
              @click="generateReport"
            >
              生成报告
            </el-button>
          </div>
        </div>
      </template>

      <el-form
        ref="policyFormRef"
        :model="policyForm"
        :rules="policyRules"
        label-width="200px"
        label-position="left"
      >
        <!-- 密码复杂度配置 -->
        <el-divider content-position="left">密码复杂度要求</el-divider>

        <el-form-item label="最小密码长度" prop="min_length">
          <el-input-number
            v-model="policyForm.min_length"
            :min="6"
            :max="32"
            controls-position="right"
          />
          <span class="form-unit">字符</span>
          <div class="form-tip">密码的最小长度要求，范围：6-32字符</div>
        </el-form-item>

        <el-form-item label="要求大写字母" prop="require_uppercase">
          <el-switch
            v-model="policyForm.require_uppercase"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">密码必须包含至少一个大写字母 (A-Z)</div>
        </el-form-item>

        <el-form-item label="要求小写字母" prop="require_lowercase">
          <el-switch
            v-model="policyForm.require_lowercase"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">密码必须包含至少一个小写字母 (a-z)</div>
        </el-form-item>

        <el-form-item label="要求数字" prop="require_numbers">
          <el-switch
            v-model="policyForm.require_numbers"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">密码必须包含至少一个数字 (0-9)</div>
        </el-form-item>

        <el-form-item label="要求特殊字符" prop="require_special_chars">
          <el-switch
            v-model="policyForm.require_special_chars"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">密码必须包含至少一个特殊字符 (!@#$%^&*等)</div>
        </el-form-item>

        <el-form-item label="特殊字符集" prop="special_chars" v-if="policyForm.require_special_chars">
          <el-input
            v-model="policyForm.special_chars"
            placeholder="请输入允许的特殊字符"
            maxlength="50"
            show-word-limit
          />
          <div class="form-tip">定义允许使用的特殊字符，默认：!@#$%^&*()_+-=[]{}|;:,.<>?</div>
        </el-form-item>

        <!-- 密码历史策略 -->
        <el-divider content-position="left">密码历史策略</el-divider>

        <el-form-item label="密码历史记录数" prop="history_size">
          <el-input-number
            v-model="policyForm.history_size"
            :min="0"
            :max="24"
            controls-position="right"
          />
          <span class="form-unit">个</span>
          <div class="form-tip">禁止使用最近N个历史密码，0表示不限制</div>
        </el-form-item>

        <el-form-item label="禁止用户名包含" prop="prevent_username_inclusion">
          <el-switch
            v-model="policyForm.prevent_username_inclusion"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">禁止密码中包含用户名</div>
        </el-form-item>

        <!-- 密码过期策略 -->
        <el-divider content-position="left">密码过期策略</el-divider>

        <el-form-item label="密码最大使用天数" prop="max_age_days">
          <el-input-number
            v-model="policyForm.max_age_days"
            :min="0"
            :max="365"
            controls-position="right"
          />
          <span class="form-unit">天</span>
          <div class="form-tip">密码的最长使用时间，0表示永不过期</div>
        </el-form-item>

        <el-form-item label="密码过期提醒天数" prop="expire_warning_days" v-if="policyForm.max_age_days > 0">
          <el-input-number
            v-model="policyForm.expire_warning_days"
            :min="1"
            :max="30"
            controls-position="right"
          />
          <span class="form-unit">天</span>
          <div class="form-tip">在密码过期前多少天开始提醒用户</div>
        </el-form-item>

        <!-- 账户锁定策略 -->
        <el-divider content-position="left">账户锁定策略</el-divider>

        <el-form-item label="最大登录失败次数" prop="max_failed_attempts">
          <el-input-number
            v-model="policyForm.max_failed_attempts"
            :min="1"
            :max="10"
            controls-position="right"
          />
          <span class="form-unit">次</span>
          <div class="form-tip">连续登录失败多少次后锁定账户</div>
        </el-form-item>

        <el-form-item label="账户锁定时间" prop="lockout_duration_minutes" v-if="policyForm.max_failed_attempts > 0">
          <el-input-number
            v-model="policyForm.lockout_duration_minutes"
            :min="5"
            :max="1440"
            :step="5"
            controls-position="right"
          />
          <span class="form-unit">分钟</span>
          <div class="form-tip">账户被锁定后的持续时间</div>
        </el-form-item>

        <!-- 高级配置 -->
        <el-divider content-position="left">高级配置</el-divider>

        <el-form-item label="启用密码强度检查" prop="strength_check_enabled">
          <el-switch
            v-model="policyForm.strength_check_enabled"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">实时检查密码强度并提供反馈</div>
        </el-form-item>

        <el-form-item label="禁止常见弱密码" prop="prevent_common_passwords">
          <el-switch
            v-model="policyForm.prevent_common_passwords"
            active-text="启用"
            inactive-text="禁用"
          />
          <div class="form-tip">禁止使用常见的弱密码（如123456、password等）</div>
        </el-form-item>

        <el-form-item label="密码强度阈值" prop="strength_threshold" v-if="policyForm.strength_check_enabled">
          <el-slider
            v-model="policyForm.strength_threshold"
            :min="1"
            :max="5"
            :step="1"
            show-stops
            :format-tooltip="formatStrengthTooltip"
          />
          <div class="form-tip">密码强度的最低要求等级</div>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 密码测试工具 -->
    <el-card class="test-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span class="card-title">密码测试工具</span>
        </div>
      </template>
      <div class="test-content">
        <el-form :model="testForm" label-width="120px">
          <el-form-item label="测试密码">
            <el-input
              v-model="testForm.password"
              type="password"
              placeholder="输入密码进行测试"
              style="width: 300px"
              show-password
            />
            <el-button
              type="primary"
              @click="testPassword"
              :loading="testing"
              style="margin-left: 12px"
            >
              测试复杂度
            </el-button>
          </el-form-item>
        </el-form>

        <div v-if="testResult" class="test-result">
          <el-divider content-position="left">测试结果</el-divider>
          <div class="result-content">
            <div class="result-item">
              <span class="result-label">密码强度:</span>
              <el-tag :type="getStrengthType(testResult.strength)">
                {{ getStrengthText(testResult.strength) }}
              </el-tag>
            </div>
            <div class="result-item">
              <span class="result-label">长度检查:</span>
              <el-tag :type="testResult.length_check ? 'success' : 'danger'">
                {{ testResult.length_check ? '通过' : '失败' }}
              </el-tag>
              <span class="result-detail">(要求: {{ policyForm.min_length }} 字符)</span>
            </div>
            <div class="result-item" v-if="policyForm.require_uppercase">
              <span class="result-label">大写字母:</span>
              <el-tag :type="testResult.uppercase_check ? 'success' : 'danger'">
                {{ testResult.uppercase_check ? '通过' : '失败' }}
              </el-tag>
            </div>
            <div class="result-item" v-if="policyForm.require_lowercase">
              <span class="result-label">小写字母:</span>
              <el-tag :type="testResult.lowercase_check ? 'success' : 'danger'">
                {{ testResult.lowercase_check ? '通过' : '失败' }}
              </el-tag>
            </div>
            <div class="result-item" v-if="policyForm.require_numbers">
              <span class="result-label">数字:</span>
              <el-tag :type="testResult.number_check ? 'success' : 'danger'">
                {{ testResult.number_check ? '通过' : '失败' }}
              </el-tag>
            </div>
            <div class="result-item" v-if="policyForm.require_special_chars">
              <span class="result-label">特殊字符:</span>
              <el-tag :type="testResult.special_char_check ? 'success' : 'danger'">
                {{ testResult.special_char_check ? '通过' : '失败' }}
              </el-tag>
            </div>
            <div class="result-item" v-if="testResult.suggestions && testResult.suggestions.length > 0">
              <span class="result-label">改进建议:</span>
              <ul class="suggestions">
                <li v-for="(suggestion, index) in testResult.suggestions" :key="index">
                  {{ suggestion }}
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </el-card>

    <!-- 策略合规性报告 -->
    <el-card class="report-card" shadow="never">
      <template #header>
        <div class="card-header">
          <span class="card-title">策略合规性报告</span>
        </div>
      </template>
      <div class="report-content">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="当前合规率">
            <el-progress
              :percentage="policyCompliance.percentage"
              :status="getComplianceStatus(policyCompliance.percentage)"
              :stroke-width="8"
            />
          </el-descriptions-item>
          <el-descriptions-item label="合规得分">
            {{ policyCompliance.score }}/{{ policyCompliance.total }}
          </el-descriptions-item>
          <el-descriptions-item label="密码复杂度">
            <el-tag :type="getComplexityType">
              {{ getComplexityText }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="安全等级">
            <el-tag :type="getSecurityLevelType">
              {{ getSecurityLevelText }}
            </el-tag>
          </el-descriptions-item>
        </el-descriptions>

        <div class="compliance-details">
          <h4>合规性详情</h4>
          <ul>
            <li v-if="policyForm.min_length >= 8" class="compliant">✓ 密码长度要求满足 (≥8字符)</li>
            <li v-else class="non-compliant">✗ 密码长度要求不足 (<8字符)</li>

            <li v-if="policyForm.require_uppercase" class="compliant">✓ 要求大写字母</li>
            <li v-else class="non-compliant">✗ 未要求大写字母</li>

            <li v-if="policyForm.require_lowercase" class="compliant">✓ 要求小写字母</li>
            <li v-else class="non-compliant">✗ 未要求小写字母</li>

            <li v-if="policyForm.require_numbers" class="compliant">✓ 要求数字</li>
            <li v-else class="non-compliant">✗ 未要求数字</li>

            <li v-if="policyForm.require_special_chars" class="compliant">✓ 要求特殊字符</li>
            <li v-else class="non-compliant">✗ 未要求特殊字符</li>

            <li v-if="policyForm.max_age_days > 0 && policyForm.max_age_days <= 90" class="compliant">✓ 密码过期策略合理</li>
            <li v-else-if="policyForm.max_age_days === 0" class="warning">⚠ 密码永不过期</li>
            <li v-else class="non-compliant">✗ 密码过期时间过长</li>
          </ul>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthAdminStore } from '@/store/modules/auth_admin'

const authAdminStore = useAuthAdminStore()
const policyFormRef = ref()

// 表单数据
const policyForm = reactive({
  min_length: 8,
  require_uppercase: true,
  require_lowercase: true,
  require_numbers: true,
  require_special_chars: true,
  special_chars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  history_size: 5,
  prevent_username_inclusion: true,
  max_age_days: 90,
  expire_warning_days: 7,
  max_failed_attempts: 5,
  lockout_duration_minutes: 30,
  strength_check_enabled: true,
  prevent_common_passwords: true,
  strength_threshold: 3
})

// 测试表单
const testForm = reactive({
  password: ''
})

const testResult = ref(null)
const testing = ref(false)

// 表单验证规则
const policyRules = {
  min_length: [
    { required: true, message: '请输入最小密码长度', trigger: 'blur' }
  ],
  max_age_days: [
    { required: true, message: '请输入密码最大使用天数', trigger: 'blur' }
  ],
  max_failed_attempts: [
    { required: true, message: '请输入最大登录失败次数', trigger: 'blur' }
  ]
}

// 计算属性
const policyCompliance = computed(() => authAdminStore.policyCompliance)
const passwordPolicyLoading = computed(() => authAdminStore.passwordPolicyLoading)

const getComplexityType = computed(() => {
  const requirements = [
    policyForm.require_uppercase,
    policyForm.require_lowercase,
    policyForm.require_numbers,
    policyForm.require_special_chars
  ]
  const enabledCount = requirements.filter(Boolean).length

  if (enabledCount >= 3) return 'success'
  if (enabledCount >= 2) return 'warning'
  return 'danger'
})

const getComplexityText = computed(() => {
  const requirements = [
    policyForm.require_uppercase,
    policyForm.require_lowercase,
    policyForm.require_numbers,
    policyForm.require_special_chars
  ]
  const enabledCount = requirements.filter(Boolean).length

  if (enabledCount >= 3) return '高'
  if (enabledCount >= 2) return '中'
  return '低'
})

const getSecurityLevelType = computed(() => {
  if (policyCompliance.value.percentage >= 80) return 'success'
  if (policyCompliance.value.percentage >= 60) return 'warning'
  return 'danger'
})

const getSecurityLevelText = computed(() => {
  if (policyCompliance.value.percentage >= 80) return '高'
  if (policyCompliance.value.percentage >= 60) return '中'
  return '低'
})

// 强度等级工具提示
const formatStrengthTooltip = (value) => {
  const levels = {
    1: '非常弱',
    2: '弱',
    3: '中等',
    4: '强',
    5: '非常强'
  }
  return levels[value] || '未知'
}

// 强度类型映射
const getStrengthType = (strength) => {
  const typeMap = {
    1: 'danger',
    2: 'warning',
    3: 'info',
    4: 'success',
    5: 'success'
  }
  return typeMap[strength] || 'info'
}

const getStrengthText = (strength) => {
  const textMap = {
    1: '非常弱',
    2: '弱',
    3: '中等',
    4: '强',
    5: '非常强'
  }
  return textMap[strength] || '未知'
}

// 合规状态
const getComplianceStatus = (percentage) => {
  if (percentage >= 80) return 'success'
  if (percentage >= 60) return 'warning'
  return 'exception'
}

// 保存策略
const savePolicy = async () => {
  try {
    await policyFormRef.value.validate()

    await authAdminStore.updatePasswordPolicy(policyForm)
    ElMessage.success('密码策略保存成功')
  } catch (error) {
    console.error('保存密码策略失败:', error)
    ElMessage.error('保存密码策略失败')
  }
}

// 重置策略
const resetPolicy = async () => {
  try {
    await ElMessageBox.confirm(
      '确定要重置所有密码策略为默认值吗？',
      '重置确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )

    await authAdminStore.resetPasswordPolicy()
    await loadPolicy()
    ElMessage.success('密码策略已重置为默认值')
  } catch (error) {
    if (error !== 'cancel') {
      console.error('重置密码策略失败:', error)
      ElMessage.error('重置密码策略失败')
    }
  }
}

// 生成报告
const generateReport = async () => {
  try {
    const response = await authAdminStore.generatePolicyReport()
    ElMessage.success('策略报告生成成功')
    console.log('策略报告:', response.data)
  } catch (error) {
    console.error('生成策略报告失败:', error)
    ElMessage.error('生成策略报告失败')
  }
}

// 测试密码
const testPassword = async () => {
  if (!testForm.password) {
    ElMessage.warning('请输入要测试的密码')
    return
  }

  try {
    testing.value = true
    const response = await authAdminStore.testPasswordComplexity(testForm.password)
    testResult.value = response.data
  } catch (error) {
    console.error('测试密码复杂度失败:', error)
    ElMessage.error('测试密码复杂度失败')
  } finally {
    testing.value = false
  }
}

// 加载策略
const loadPolicy = async () => {
  try {
    const response = await authAdminStore.loadPasswordPolicy()
    if (response.data) {
      Object.assign(policyForm, response.data)
    }
  } catch (error) {
    console.error('加载密码策略失败:', error)
    ElMessage.error('加载密码策略失败')
  }
}

onMounted(() => {
  loadPolicy()
})
</script>

<style scoped>
.password-policy {
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

.policy-card,
.test-card,
.report-card {
  margin-bottom: 24px;
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

.test-content {
  padding: 16px 0;
}

.test-result {
  margin-top: 20px;
}

.result-content {
  padding: 16px 0;
}

.result-item {
  display: flex;
  align-items: center;
  margin-bottom: 12px;
  gap: 12px;
}

.result-label {
  width: 100px;
  font-weight: 500;
  color: #606266;
}

.result-detail {
  font-size: 12px;
  color: #909399;
}

.suggestions {
  margin: 8px 0 0 20px;
  color: #606266;
  font-size: 14px;
}

.suggestions li {
  margin-bottom: 4px;
}

.report-content {
  padding: 16px 0;
}

.compliance-details {
  margin-top: 20px;
}

.compliance-details h4 {
  margin-bottom: 12px;
  color: #303133;
}

.compliance-details ul {
  list-style: none;
  padding: 0;
}

.compliance-details li {
  margin-bottom: 8px;
  padding: 8px 12px;
  border-radius: 4px;
  background: #f5f7fa;
}

.compliant {
  color: #52c41a;
  background: #f6ffed !important;
}

.non-compliant {
  color: #f5222d;
  background: #fff2f0 !important;
}

.warning {
  color: #fa8c16;
  background: #fff7e6 !important;
}
</style>