<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-sonner';
	import { userSignIn, updateUserPassword } from '$lib/apis/auths';
	import { user as userStore } from '$lib/stores';
	import { getBackendConfig } from '$lib/apis';
	import { config as configStore } from '$lib/stores';
	
	let currentPassword = '';
	let newPassword = '';
	let confirmNewPassword = '';
	let email = '';
	let password = '';
	
	onMount(() => {
		// 从localStorage获取过期账户的信息
		email = localStorage.getItem('expired_email') || '';
		password = localStorage.getItem('expired_password') || '';
		
		if (!email || !password) {
			// 如果没有过期账户信息，重定向到登录页面
			goto('/auth');
		}
	});
	
	const changePasswordHandler = async () => {
		if (newPassword !== confirmNewPassword) {
			toast.error('新密码和确认密码不匹配');
			return;
		}
		
		if (newPassword.length < 8) {
			toast.error('密码长度至少为8位');
			return;
		}
		
		try {
			// 更新密码
			const result = await updateUserPassword('', password, newPassword);
			
			if (result) {
				toast.success('密码修改成功');
				
				// 清除localStorage中的临时信息
				localStorage.removeItem('expired_email');
				localStorage.removeItem('expired_password');
				
				// 使用新密码自动登录
				const sessionUser = await userSignIn(email, newPassword);
				if (sessionUser) {
					// 设置用户会话
					await setSessionUser(sessionUser);
				} else {
					// 如果自动登录失败，跳转到登录页面
					goto('/auth');
				}
			}
		} catch (error) {
			toast.error(`修改密码失败: ${error}`);
		}
	};
	
	const setSessionUser = async (sessionUser) => {
		if (sessionUser) {
			toast.success('登录成功');
			if (sessionUser.token) {
				localStorage.token = sessionUser.token;
			}
			userStore.set(sessionUser);
			configStore.set(await getBackendConfig());
			goto('/');
		}
	};
</script>

<div class="w-full h-screen max-h-[100dvh] text-white relative" id="change-password-page">
	<div class="w-full h-full absolute top-0 left-0 bg-white dark:bg-black"></div>
	
	<div class="w-full absolute top-0 left-0 right-0 h-8 drag-region"></div>
	
	<div class="fixed bg-transparent min-h-screen w-full flex justify-center font-primary z-50 text-black dark:text-white">
		<div class="w-full px-10 min-h-screen flex flex-col text-center">
			<div class="my-auto flex flex-col justify-center items-center">
				<div class="sm:max-w-md my-auto pb-10 w-full dark:text-gray-100">
					<div class="mb-1">
						<div class="text-2xl font-medium">
							修改密码
						</div>
						<div class="mt-1 text-xs font-medium text-gray-600 dark:text-gray-500">
							您的密码已过期，请修改密码以继续使用系统
						</div>
					</div>
					
					<form class="flex flex-col justify-center" on:submit|preventDefault={changePasswordHandler}>
						<div class="flex flex-col mt-4">
							<div>
								<label for="newPassword" class="text-sm font-medium text-left mb-1 block">
									新密码
								</label>
								<input
									bind:value={newPassword}
									type="password"
									id="newPassword"
									class="my-0.5 w-full text-sm outline-hidden bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-600"
									placeholder="输入新密码"
									required
								/>
							</div>
							
							<div class="mt-2">
								<label for="confirmNewPassword" class="text-sm font-medium text-left mb-1 block">
									确认新密码
								</label>
								<input
									bind:value={confirmNewPassword}
									type="password"
									id="confirmNewPassword"
									class="my-0.5 w-full text-sm outline-hidden bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-600"
									placeholder="再次输入新密码"
									required
								/>
							</div>
							
							<button
								type="submit"
								class="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
							>
								修改密码
							</button>
						</div>
					</form>
				</div>
			</div>
		</div>
	</div>
</div>