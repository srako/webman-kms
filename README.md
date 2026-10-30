# srako/webman-kms

Webman 插件：从**阿里云 KMS 本地代理（Agent/Sidecar）**取数据库 / Redis 凭据，替代 env.yaml 明文。

- 代理协议：`GET http://localhost:2025/secretsmanager/get?secretId=<id>`，请求头 `X-KMS-Token` 读取自 `/var/run/kmstoken`
- 凭据只存在各进程内存（TTL `cache_ttl`），不落盘
- 内置轮换监控进程，密钥轮换后自动 `reload`
- 未启用 / 拉取失败返回 `null`，调用方用 `??` 回退明文，本地开发零影响
- 不打印任何明文密码与 token

## 安装

```bash
composer require srako/webman-kms
```

插件会拷贝 `config/plugin/srako/kms/{app.php,command.php,process.php}` 到项目；之后的 `composer update` 只补齐缺失文件，不覆盖已有文件（`command.php` / `process.php` 需随包升级时请手动同步）。

## 配置（config/plugin/srako/kms/app.php）

```php
return [
    'enable' => true,                          // 总开关；false = 全部回退明文
    'endpoint' => 'http://localhost:2025/secretsmanager/get',
    'token_file' => '/var/run/kmstoken',
    'timeout' => 3,
    'cache_ttl' => 3600,                       // 进程内缓存有效期（秒）
    'monitor_interval' => 60,                  // 轮换轮询间隔（秒）；0 = 关闭；运行中改值需 restart
    'fail_cooldown' => 30,                      // 拉取失败后的负缓存（秒）
    'strict' => false,                         // true = 取不到密钥时中断启动
    'secrets' => [
        'mysql' => 'test-mysql8',              // 简写：取 AccountName / AccountPassword
        'redis' => [
            'secret_id' => 'test-redis',
            'include_username' => true,        // ACL 模式；经典模式设 false
            // 'user_field' => 'AccountName',  // 字段名非标准时覆盖
            // 'pass_field' => 'AccountPassword',
        ],
    ],
];
```

修改后 `php webman reload` 生效。kms 配置不再经 env.yaml / Nacos 下发（旧版 `kms:` 段已失效，请清理）。

> 首次把 `enable` 改为 `true`、或修改 `process.php`（count / handler）后必须 `php webman restart`：插件进程只在 master 启动时注册，`reload` 不会创建 `rotation_monitor`。是否真的在跑用 `php start.php status | grep rotation_monitor` 确认（`kms:check` 只按配置推断，不检查进程）。

## 接入示例

```php
$kmsMysql = kms_credentials('mysql');
'username' => $kmsMysql['username'] ?? yaml('database.mysql.username', ''),
'password' => $kmsMysql['password'] ?? yaml('database.mysql.password', ''),

$kmsRedis = kms_credentials('redis');
'username' => $kmsRedis['username'] ?? yaml('redis.username', ''),
'password' => $kmsRedis['password'] ?? yaml('redis.password', null),

// workerman/redis 原生 client 与 phpredis（config/session.php）都用 auth 键
'auth' => kms_redis_auth($kmsRedis) ?? yaml('redis.password'),
```

| 函数 | 说明 |
| --- | --- |
| `kms_credentials($alias)` | `['username' => ..., 'password' => ...]`；未启用 / 未配置 / 失败时 `null` |
| `kms_secret($secretId, $fresh = false)` | 原始 SecretData 数组 |
| `kms_enabled()` | 配置中 `enable === true` |
| `kms_redis_auth($creds)` | ACL → `['user'=>..., 'pass'=>...]`；经典 → 密码串；无凭据 → `null` |

## 命令

```bash
php webman kms:check                    # 各 alias 来源 / 版本 / 年龄
php webman kms:check --fresh            # 绕过进程内缓存
php webman kms:check --test-connections # 附加 MySQL SELECT 1 与 Redis PING
php webman kms:check --json             # 机器可读输出
```

退出码：`0` 正常（含未启用）、`1` 已启用但 secrets 未配置、`2` 拉取失败、`3` 连接测试失败。

## 回退与轮换

解析链：`内存缓存 → HTTP 拉取 → null`（`strict: true` 时抛异常）。

- 拉取失败有 `fail_cooldown` 负缓存，避免启动期反复请求挂起的代理
- 进程重启 / reload 后不继承旧配置，新 worker 首次调用即重读 `app.php` 并重新拉取，改 `secret_id` 后 `reload` 立即生效
- 非 `strict` 下，reload 后若 Agent 暂时不可用，会回退到父进程继承的最后一次成功凭据（日志标记 inherited，`kms:check` 的 source 显示 inherited），Agent 恢复后自动换新；`strict: true` 下不回退，直接失败（reload 前请确认 Agent 可用）
- `RotationMonitor`（独立进程 count=1，不随 reload 重启）每轮重读 `app.php`，每 `monitor_interval` 秒比对 VersionId，检测到轮换或代理恢复即向 master 发 `SIGUSR1` 触发优雅 reload；`monitor_interval` 在进程启动时读取，运行中修改需 restart
- 自愈：连续 10 轮全部失败、或 fd 数较基线增长超 50 时进程退出，由 master 拉起

> `strict: true` 时若代理不可用，宿主 config 会在 bootstrap 阶段抛异常，`kms:check` 也无法启动——排查先恢复代理或临时置 `false`。

## ECS 侧准备（阿里云 KMS Agent）

控制台 → **应用接入** → **云原生接入** → **弹性计算**，选中 Linux ECS（运行中）点击配置：

1. 认证方式二选一：**实例身份**（推荐，勾选所需 RBAC 权限如 `CryptoServiceSecretUser`）或 **RAMRole**（策略需含 `kms:GetSecretValue`、`kms:Decrypt`）
2. 填本地端口（默认 `2025`）、KMS 地域与访问域名（共享网关 `kms-vpc.<region>.aliyuncs.com` 或实例专有域名），确认后由云助手安装
3. Agent 仅监听 `127.0.0.1:2025`；ECS 需能访问所选 KMS 域名
4. 应用进程需对 `/var/run/kmstoken` 可读；Docker 部署需把该文件只读挂载进容器，并确保容器能访问 Agent（`--network host`、与 Agent 共享网络命名空间 / 同 Pod，或把 `endpoint` 改成宿主机地址）——容器内的 `localhost` 指向容器自身

验证（返回 `200` 即连通且有权限）：

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "X-KMS-Token:$(cat /var/run/kmstoken)" \
  'http://localhost:2025/secretsmanager/get?secretId=<secret-id>'
```

常见问题：

| 现象 | 排查方向 |
| --- | --- |
| `Connection refused` / 超时 | Agent 未安装或未启动；端口变更需同步 `endpoint` |
| token 为空或读取失败 | `/var/run/kmstoken` 不存在 / 不可读；容器未挂载 |
| `SecretNotFound` | `secrets` 里的 secretId 与控制台不一致 |
| `AccessDenied` | RBAC 权限或 RAM 策略缺少 `kms:GetSecretValue`、`kms:Decrypt` |
| 改 secretId 后仍连旧账号 | 是否已 `php webman reload` |

## 从明文迁移

1. 配好 `enable` + `secrets`，`php webman kms:check` 全绿
2. 删除 env.yaml（含 Nacos）中对应明文，`kms:check --test-connections` 复验
3. 开启 `strict: true`
