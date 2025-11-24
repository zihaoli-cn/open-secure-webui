"""
Open WebUI API客户端
提供与Open WebUI后端API的集成功能
"""
import httpx
import logging
from typing import Optional, Dict, Any, List
from config import settings

logger = logging.getLogger(__name__)


class OpenWebUIClient:
    """Open WebUI API客户端"""

    def __init__(self):
        self.base_url = settings.OPENWEBUI_URL.rstrip('/')
        self.api_key = settings.OPENWEBUI_API_KEY
        self.timeout = 30

    async def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        发送HTTP请求到Open WebUI API
        """
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
        }

        # 添加API密钥认证
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if method.upper() == "GET":
                    response = await client.get(url, headers=headers, params=data)
                elif method.upper() == "POST":
                    response = await client.post(url, headers=headers, json=data)
                elif method.upper() == "PUT":
                    response = await client.put(url, headers=headers, json=data)
                elif method.upper() == "DELETE":
                    response = await client.delete(url, headers=headers)
                else:
                    raise ValueError(f"不支持的HTTP方法: {method}")

                response.raise_for_status()
                return response.json()

        except httpx.HTTPError as e:
            logger.error(f"Open WebUI API请求失败: {e}")
            raise
        except Exception as e:
            logger.error(f"Open WebUI API请求异常: {e}")
            raise

    async def get_admin_user(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        通过API密钥获取管理员用户信息
        模拟Open WebUI的get_admin_user功能
        """
        try:
            # 这里应该调用Open WebUI的实际API来验证API密钥
            # 由于Open WebUI的具体API端点未知，我们先返回一个模拟的用户信息
            # 在实际部署时需要替换为真实的API调用

            # 模拟验证逻辑
            if api_key == "valid_admin_key":
                return {
                    "id": 1,
                    "username": "admin",
                    "role": "admin",
                    "permissions": ["user_management", "model_management"]
                }
            return None

        except Exception as e:
            logger.error(f"获取管理员用户信息失败: {e}")
            return None

    async def get_current_user_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        通过API密钥获取当前用户信息
        模拟Open WebUI的get_current_user_by_api_key功能
        """
        try:
            # 这里应该调用Open WebUI的实际API
            # 由于Open WebUI的具体API端点未知，我们先返回一个模拟的用户信息

            # 模拟验证逻辑
            if api_key.startswith("sk-"):
                return {
                    "id": 1,
                    "username": "api_user",
                    "role": "user",
                    "permissions": ["chat", "models"]
                }
            return None

        except Exception as e:
            logger.error(f"通过API密钥获取用户信息失败: {e}")
            return None

    async def generate_api_key(self, user_id: str, name: str, permissions: List[str]) -> Optional[str]:
        """
        生成API密钥
        模拟Open WebUI的generate_api_key功能
        """
        try:
            # 这里应该调用Open WebUI的实际API
            # 由于Open WebUI的具体API端点未知，我们生成一个模拟的API密钥

            import secrets
            import string

            # 生成随机的API密钥
            alphabet = string.ascii_letters + string.digits
            api_key = 'sk-' + ''.join(secrets.choice(alphabet) for _ in range(32))

            logger.info(f"为用户 {user_id} 生成API密钥: {name}")
            return api_key

        except Exception as e:
            logger.error(f"生成API密钥失败: {e}")
            return None

    async def get_users(self) -> List[Dict[str, Any]]:
        """获取用户列表"""
        try:
            # 模拟用户数据
            return [
                {
                    "id": 1,
                    "username": "user1",
                    "email": "user1@example.com",
                    "role": "user",
                    "created_at": "2024-01-01T00:00:00Z"
                },
                {
                    "id": 2,
                    "username": "user2",
                    "email": "user2@example.com",
                    "role": "user",
                    "created_at": "2024-01-02T00:00:00Z"
                }
            ]
        except Exception as e:
            logger.error(f"获取用户列表失败: {e}")
            return []

    async def get_models(self) -> List[Dict[str, Any]]:
        """获取模型列表"""
        try:
            # 模拟模型数据
            return [
                {
                    "id": "gpt-3.5-turbo",
                    "name": "GPT-3.5 Turbo",
                    "provider": "openai",
                    "enabled": True
                },
                {
                    "id": "claude-3-sonnet",
                    "name": "Claude 3 Sonnet",
                    "provider": "anthropic",
                    "enabled": True
                }
            ]
        except Exception as e:
            logger.error(f"获取模型列表失败: {e}")
            return []

    async def get_groups(self) -> List[Dict[str, Any]]:
        """获取用户组列表"""
        try:
            # 模拟组数据
            return [
                {
                    "id": 1,
                    "name": "默认组",
                    "description": "默认用户组",
                    "member_count": 10
                },
                {
                    "id": 2,
                    "name": "VIP组",
                    "description": "VIP用户组",
                    "member_count": 5
                }
            ]
        except Exception as e:
            logger.error(f"获取用户组列表失败: {e}")
            return []


# 创建全局客户端实例
openwebui_client = OpenWebUIClient()