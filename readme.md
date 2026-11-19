#
# 植物种植花期管理系统

个人向的植物种植 / 花期 / 养护 / 病害资料库。FastAPI + SQLite + 原生前端，单机单账号运行，不依赖任何外网 CDN。

> 新增植物时可点「网络图片」按名称搜索候选图（Bing / 360 / 维基共享资源），并可点「AI 补齐」由免费 AI 生成规范资料。头部「AI 问答」只回答植物相关话题。免费 AI 默认使用 DeepSeek V4 Flash 免密钥通道，额度用尽会自动降级并弹框提示。在「设置 → AI 设置」填入兼容 OpenAI 的 API Key 后，AI 问答与 AI 补齐都会改用自有模型（可填 DeepSeek V4.1 的地址与模型）。以上联网功能需要服务器能访问外网。


## 一、依赖环境

```shell
sudo pip3 install -r requirements.txt
```

Python 3.8+（SQLite 使用标准库 `sqlite3`，无需额外数据库服务）。

## 二、使用方法

```shell
python3 main.py                 # 启动（默认 8002 端口）
python3 main.py stop            # 按端口停止服务
python3 main.py migrate         # 手动初始化/迁移数据库并查看统计
```

可用环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PLANT_PORT` | `8002` | 监听端口 |
| `PLANT_HOST` | `0.0.0.0` | 监听地址 |
| `PLANT_DATA_DIR` | `./data` | 数据目录 |
| `PLANT_DB_PATH` | `$PLANT_DATA_DIR/plants.db` | SQLite 文件路径 |
| `PLANT_NO_MPORT` | 空 | 设为任意值时不调用 `mport` 登记端口 |
| `PLANT_AI_FREE_URL` | `https://api.llm7.io/v1/chat/completions` | 主免费 AI 接口（免密钥） |
| `PLANT_AI_FREE_MODEL` | `DeepSeek-V4-Flash-0731` | 主免费 AI 模型名 |
| `PLANT_AI_FREE_LABEL` | `DeepSeek V4 Flash（免费）` | 界面展示的免费模型名称 |
| `PLANT_AI_ENDPOINT` | `https://text.pollinations.ai/openai` | 备用免费 AI 接口（主通道额度用尽时自动降级） |
| `PLANT_AI_MODEL` | `openai-fast` | 备用免费 AI 模型名 |
| `PLANT_AI_FREE_TIMEOUT` | `30` | 主免费通道超时秒数，超时后自动降级 |
| `PLANT_AI_BACKUP_TIMEOUT` | `50` | 备用免费通道超时秒数 |
| `PLANT_AI_TIMEOUT` | `90` | 自有 AI 接口超时秒数 |

### 旧 JSON 数据迁移

首次以新版启动时会自动检测并迁移：

- `data/植物数据库.json` → `plants` / `user_plants` / `todo_done` 表
- `data/auth.json`（旧版单账号）→ `users` 表，旧密码哈希保留，首次成功登录后自动升级为 PBKDF2

迁移前会在 `data/backup/` 生成原始 JSON 备份，原 JSON 文件保留不删除；`meta` 表记录迁移标记，避免重复导入。旧版 `todoDone` 没有年月，迁移时统一归入当前月份。

## 三、源码说明

```text
web_plant_manage/
├── main.py             # FastAPI 路由、认证、图片代理、进程管理
├── db.py               # SQLite 表结构、旧数据迁移、业务读写
├── index.html          # 单页前端
├── static/
│   ├── vendor/         # 本地化的 tailwind / axios / font-awesome
│   └── fonts/          # font-awesome 字体
├── requirements.txt
└── data/               # 运行数据（已忽略，首次启动自动创建）
```

### 数据存储

SQLite 开启 `WAL`、`foreign_keys`、`busy_timeout`；所有写操作使用 `BEGIN IMMEDIATE` 事务，解决旧版“整库读-改-写”并发覆盖问题。

| 表 | 用途 |
| --- | --- |
| `plants` | 总植物库（id、名称、地区、种植时间、花期、介绍、养护、病害、图片） |
| `user_plants` | “我的种植”引用（外键级联删除） |
| `todo_done` | 待办勾选，主键 `(plant_id, period)`，`period` 为 `YYYY-MM`，按月独立 |
| `diseases` | 病害库：名称、症状、治理方法、预防措施 |
| `users` | 单账号，PBKDF2-HMAC-SHA256（26 万次迭代 + 随机盐） |
| `sessions` | 登录会话（仅存 token 哈希，30 天过期，重启不掉线） |
| `meta` | 迁移标记等元数据 |

备份策略：

- 迁移旧 JSON 前自动备份原始 JSON；
- 迁移前用 SQLite 在线备份 API 生成 `data/backup/` 快照，目录最多保留 20 个文件。

### 主要接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/auth/status` / `/api/auth/me` | 注册状态 / 当前登录用户 |
| POST | `/api/auth/login` / `register` / `logout` | 登录、初始化注册、登出（HttpOnly Cookie） |
| GET | `/api/all` | 全量数据（植物、我的种植、当月待办、病害库） |
| POST | `/api/plant/save` | 新增/编辑，同名复用；重名冲突返回 409 |
| POST | `/api/plant/delete_user` / `delete_store` | 移出我的种植 / 彻底删除 |
| POST | `/api/todo/toggle` | 勾选/取消当月待办，可传 `period` |
| GET | `/api/diseases` | 病害库列表 |
| POST | `/api/disease/save` / `delete` | 病害新增/编辑/删除 |
| POST | `/api/image/fetch` | 服务端拉取图片转 base64，绕过浏览器跨域限制 |
| GET | `/api/image/search` | 按名称搜索网络图片，返回最多 10 个候选（Bing / 360 / 维基共享资源） |
| GET | `/api/image/proxy` | 缩略图代理，规避防盗链与跨域 |
| POST | `/api/plant/ai_fill` | 按植物名称调用 AI 生成地区、种植时间、花期、介绍、养护，并按病害库匹配病害 |
| POST | `/api/ai/chat` | 植物话题问答，服务端会拦截明显无关的问题 |
| GET / POST | `/api/ai/config` | 读取 / 保存自有 AI 的 API Key、地址与模型；Key 不回传明文 |
| POST | `/api/ai/test` | 用当前配置发一条最小请求测试连通性 |
| GET | `/api/health` | 健康检查与数据统计 |

## 四、修改记录

### V1.1.0

存储从 JSON 文件迁移到本地 SQLite，并修复以下问题：

1. 本地上传图片保存为 `blob:` 地址导致刷新后图片失效；改为压缩后 base64 持久化（最长边 1280px JPEG）。
2. 本月待办勾选状态不带年月，跨月/跨年不重置；改为 `(plant_id, period)` 按月存储。
3. 同时写入会整库覆盖丢失数据；改为事务 + WAL，并通过 20 并发写入测试。
4. 编辑改名可制造重名，且同名匹配随机命中；新增/改名重名返回 409，历史重名保留并提示处理。
5. 登录 token 只存在内存，重启即全体掉线；改为 SQLite 持久化会话（30 天，仅存哈希）。
6. 整库导入无校验，非法 JSON 可覆盖并打挂数据；已下线整库导入/导出入口，写入统一走单事务。
7. 密码使用无盐 SHA256；改为 PBKDF2 + 随机盐，旧哈希登录时自动升级。
8. 页面依赖公网 CDN，内网/断网不可用；tailwind、axios、font-awesome 全部本地化。
9. URL 图片受浏览器跨域限制加载失败；新增服务端图片代理。
10. 登录暴力尝试无限制；增加同 IP 5 分钟 8 次失败限流。
11. 清理无效代码与遗留文件：`login.html`（读取不存在的 `sessionId`）已删除；`/` 路由冗余鉴权已移除。
12. 新增病害库管理界面：病害统一维护症状/治理/预防，植物卡片可查看匹配到的病害详情。
13. 新增按植物名称的网络图片搜索（Bing/360/维基共享资源）与 AI 资料补齐；补齐结果缓存 6 小时。
14. 新增「AI 问答」与「AI 设置」：问答强制限定植物话题（提示词约束 + 服务端关键词拦截）；可在设置中保存 OpenAI 兼容接口的 Key/地址/模型，保存后 AI 问答与 AI 补齐统一走自有模型，未配置时使用免费 AI。
15. 免费 AI 默认使用 DeepSeek V4 Flash 免密钥通道，额度用尽时自动降级到备用免费模型，并弹框提示注册与配置 API Key（附 DeepSeek V4.1 的地址和模型填写指引）。

## Todo

- 多用户 / 多人共享权限（当前仍为单账号）。
- 植物图片独立文件存储（当前 base64 存在 SQLite 中）。
