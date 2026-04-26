# Windsurf Automation Toolkit

用于批量注册 Windsurf 账号、保存鉴权产物，并在本地浏览器环境里复用这些会话。


## 功能

- 批量注册 Windsurf 账号并写出鉴权产物
- 将鉴权产物转换为 Camoufox 可复用的会话格式
- 按账号顺序打开定价页，便于人工处理支付流程

## 脚本说明

- `windsurf_register.py`: 通过 CloudMail API 批量创建邮箱、注册 Windsurf、保存会话文件
- `camoufox_windsurf.py`: 用单个保存的会话在 Camoufox 中打开 Windsurf
- `camoufox_pricing_queue.py`: 依次用多个保存的会话打开定价页
- `playwright_windsurf.py`: 用 Playwright Chromium 复用保存的会话
- `windsurf_session.py`: 浏览器脚本共享的会话归一化与注入工具

## 环境要求

- Python 3.14+
- CloudMail 


## 安装

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -r requirements.txt
```

安装完 Python 依赖后，再执行浏览器初始化：

```powershell
python -m camoufox fetch
```


## 配置

把 `.env.example` 复制为 `.env`，并替换成你自己的 CloudMail 与本地服务配置。

必填字段：

- `CLOUDMAIL_BASE_URL`
- `CLOUDMAIL_ADMIN_EMAIL`
- `CLOUDMAIL_ADMIN_PASSWORD`
- `CLOUDMAIL_DOMAIN`

可选字段：

- `EMAIL_PREFIX_LENGTH`
- `REGISTER_PASSWORD_LENGTH`
- `DISPLAY_NAME_LENGTH`
- `CLOUDMAIL_POLL_INTERVAL_SECONDS`
- `CLOUDMAIL_POLL_TIMEOUT_SECONDS`
- `WINDSURF_POOL_API_BASE_URL`

当前示例文件见 `.env.example`，其中字段含义如下：

- `CLOUDMAIL_BASE_URL`: CloudMail OpenAPI 地址
- `CLOUDMAIL_ADMIN_EMAIL`: 用于调用 `/api/public/genToken` 的管理员账号
- `CLOUDMAIL_ADMIN_PASSWORD`: 管理员密码
- `CLOUDMAIL_DOMAIN`: 新注册邮箱所使用的域名，不带 `@`
- `EMAIL_PREFIX_LENGTH`: 随机邮箱前缀长度
- `REGISTER_PASSWORD_LENGTH`: 注册账号生成的密码长度
- `DISPLAY_NAME_LENGTH`: 注册账号显示名中的随机串长度
- `CLOUDMAIL_POLL_INTERVAL_SECONDS`: 轮询邮件间隔
- `CLOUDMAIL_POLL_TIMEOUT_SECONDS`: 等待验证码邮件的超时时间
- `WINDSURF_POOL_API_BASE_URL`: WindsurfPoolAPI 导入地址

## 常用命令

批量注册账号：

```powershell
python windsurf_register.py --count  --output-dir auth_output
```


依次打开所有账号的试用页：

```powershell
python camoufox_pricing_queue.py --non-interactive --accounts-root auth_output --url https://windsurf.com/pricing
```



## 输出目录

- `auth_output/`: 每个账号一份鉴权文件与汇总文件
- `.camoufox-pricing-queue/`: Camoufox 顺序打开定价页时的本地 profile

## 鸣谢

[LINUX DO - 新的理想型社区](https://linux.do)

