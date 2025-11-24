#!/bin/bash

# 三员管理系统API测试脚本

BASE_URL="http://localhost:3001"
API_URL="$BASE_URL/api"

echo "========================================="
echo "三员管理系统API测试"
echo "========================================="

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 测试健康检查
echo -e "\n1. 测试健康检查..."
HEALTH=$(curl -s "$BASE_URL/health")
if echo "$HEALTH" | grep -q "healthy"; then
    echo -e "${GREEN}✓ 健康检查通过${NC}"
else
    echo -e "${RED}✗ 健康检查失败${NC}"
    exit 1
fi

# 测试sys_admin登录
echo -e "\n2. 测试sys_admin登录..."
SYS_ADMIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"sys_admin","password":"SysAdmin123!"}')

SYS_ADMIN_TOKEN=$(echo "$SYS_ADMIN_RESPONSE" | jq -r '.access_token')
if [ "$SYS_ADMIN_TOKEN" != "null" ] && [ -n "$SYS_ADMIN_TOKEN" ]; then
    echo -e "${GREEN}✓ sys_admin登录成功${NC}"
else
    echo -e "${RED}✗ sys_admin登录失败${NC}"
    exit 1
fi

# 测试auth_admin登录
echo -e "\n3. 测试auth_admin登录..."
AUTH_ADMIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"auth_admin","password":"AuthAdmin123!"}')

AUTH_ADMIN_TOKEN=$(echo "$AUTH_ADMIN_RESPONSE" | jq -r '.access_token')
if [ "$AUTH_ADMIN_TOKEN" != "null" ] && [ -n "$AUTH_ADMIN_TOKEN" ]; then
    echo -e "${GREEN}✓ auth_admin登录成功${NC}"
else
    echo -e "${RED}✗ auth_admin登录失败${NC}"
    exit 1
fi

# 测试audit_admin登录
echo -e "\n4. 测试audit_admin登录..."
AUDIT_ADMIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"audit_admin","password":"AuditAdmin123!"}')

AUDIT_ADMIN_TOKEN=$(echo "$AUDIT_ADMIN_RESPONSE" | jq -r '.access_token')
if [ "$AUDIT_ADMIN_TOKEN" != "null" ] && [ -n "$AUDIT_ADMIN_TOKEN" ]; then
    echo -e "${GREEN}✓ audit_admin登录成功${NC}"
else
    echo -e "${RED}✗ audit_admin登录失败${NC}"
    exit 1
fi

# 测试sys_admin API Keys接口
echo -e "\n5. 测试sys_admin API Keys接口..."
API_KEYS_RESPONSE=$(curl -s -H "Authorization: Bearer $SYS_ADMIN_TOKEN" \
    "$API_URL/sys-admin/api-keys")

if echo "$API_KEYS_RESPONSE" | jq -e '.api_keys' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API Keys接口正常${NC}"
else
    echo -e "${RED}✗ API Keys接口失败${NC}"
    echo "$API_KEYS_RESPONSE"
fi

# 测试auth_admin安全配置接口
echo -e "\n6. 测试auth_admin安全配置接口..."
SECURITY_CONFIG_RESPONSE=$(curl -s -H "Authorization: Bearer $AUTH_ADMIN_TOKEN" \
    "$API_URL/auth-admin/security-config")

if echo "$SECURITY_CONFIG_RESPONSE" | jq -e '.' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 安全配置接口正常${NC}"
else
    echo -e "${RED}✗ 安全配置接口失败${NC}"
    echo "$SECURITY_CONFIG_RESPONSE"
fi

# 测试audit_admin审计日志接口
echo -e "\n7. 测试audit_admin审计日志接口..."
AUDIT_LOGS_RESPONSE=$(curl -s -H "Authorization: Bearer $AUDIT_ADMIN_TOKEN" \
    "$API_URL/audit-admin/logs?limit=10")

if echo "$AUDIT_LOGS_RESPONSE" | jq -e '.logs' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 审计日志接口正常${NC}"
else
    echo -e "${RED}✗ 审计日志接口失败${NC}"
    echo "$AUDIT_LOGS_RESPONSE"
fi

# 测试权限隔离
echo -e "\n8. 测试权限隔离..."
FORBIDDEN_RESPONSE=$(curl -s -H "Authorization: Bearer $AUDIT_ADMIN_TOKEN" \
    "$API_URL/sys-admin/api-keys")

if echo "$FORBIDDEN_RESPONSE" | grep -q "需要系统管理员权限"; then
    echo -e "${GREEN}✓ 权限隔离正常${NC}"
else
    echo -e "${RED}✗ 权限隔离失败${NC}"
    echo "$FORBIDDEN_RESPONSE"
fi

# 测试密码修改
echo -e "\n9. 测试密码修改..."
CHANGE_PASSWORD_RESPONSE=$(curl -s -X POST "$API_URL/auth/change-password" \
    -H "Authorization: Bearer $SYS_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"current_password":"SysAdmin123!","new_password":"SysAdmin123!"}')

if echo "$CHANGE_PASSWORD_RESPONSE" | jq -e '.success' > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 密码修改接口正常${NC}"
else
    echo -e "${RED}✗ 密码修改接口失败${NC}"
    echo "$CHANGE_PASSWORD_RESPONSE"
fi

echo -e "\n========================================="
echo -e "${GREEN}所有测试完成！${NC}"
echo "========================================="
