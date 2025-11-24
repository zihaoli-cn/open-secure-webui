#!/bin/bash

# 三员管理系统后端启动脚本

echo "========================================="
echo "三员管理系统后端启动脚本"
echo "========================================="

# 检查Python版本
echo "检查Python版本..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python版本: $python_version"

# 检查虚拟环境
if [ ! -d "venv" ]; then
    echo "创建虚拟环境..."
    python3 -m venv venv
fi

# 激活虚拟环境
echo "激活虚拟环境..."
source venv/bin/activate

# 安装依赖
echo "安装依赖..."
pip install -r requirements.txt --quiet

# 检查.env文件
if [ ! -f ".env" ]; then
    echo "警告: .env文件不存在，将使用默认配置"
fi

# 启动服务
echo "启动后端服务..."
echo "服务地址: http://0.0.0.0:3001"
echo "API文档: http://localhost:3001/docs"
echo "========================================="

python main.py
