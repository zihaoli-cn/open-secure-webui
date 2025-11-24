#!/bin/bash

# 三员管理系统前端启动脚本

echo "========================================="
echo "三员管理系统前端启动脚本"
echo "========================================="

# 检查Node.js版本
echo "检查Node.js版本..."
node_version=$(node --version 2>&1)
echo "Node.js版本: $node_version"

# 检查npm版本
npm_version=$(npm --version 2>&1)
echo "npm版本: $npm_version"

# 检查node_modules
if [ ! -d "node_modules" ]; then
    echo "安装依赖..."
    npm install
else
    echo "依赖已安装"
fi

# 检查.env文件
if [ ! -f ".env" ]; then
    echo "警告: .env文件不存在，将使用默认配置"
fi

# 启动开发服务器
echo "启动前端开发服务器..."
echo "服务地址: http://localhost:3002"
echo "========================================="

npm run dev
