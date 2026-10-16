# srako/webman-kms

Webman 通用 composer 包：从**阿里云 KMS 本地代理（sidecar）**获取数据库/Redis 凭据，替代 env.yaml 明文。

- 本地代理协议：`GET http://localhost:2025/secretsmanager/get?secretId=<id>`，请求头 `X-KMS-Token` 取自 `/var/run/kmstoken`
- **纯内存缓存**：凭据只存在于各进程内存（TTL `cache_ttl`），不落盘、无需清理
- **轮换监控**：插件自带独立监控进程，密钥轮换后自动优雅 reload（无需 cron / 预热）
- 未启用 / 拉取失败时返回 `null`，调用方以 `??` 回退 env.yaml 明文，**本地开发零影响**
- 自带 `php webman kms:check` 自检命令（连通性 / 密钥 / 数据库与 Redis 连接测试）
- 不打印任何明文密码与 token

## 安装

```bash
composer require srako/webman-kms
```

安装时 webman 插件机制会把 `config/plugin/srako/kms/{app.php,command.php,process.php}` 拷入项目；之后 `composer update` 只补齐缺失文件，不会覆盖已改过的 `app.php`。

## 配置（config/plugin/srako/kms/app.php）

```php
return [
    'enable' => true,                              // 总开关；false = 全部回退 env.yaml 明文
    'endpoint' => 'http://localhost:2025/secretsmanager/get',
    'token_file' => '/var/run/kmstoken',
    'timeout' => 3,
    'cache_ttl' => 3600,                           // 进程内缓存有效期（秒）
    'monitor_interval' => 60,                      // 轮换监控轮询间隔（秒）；0 = 关闭
    'fail_cooldown' => 30,                         // 拉取失败后的进程内负缓存时长（秒）
    'strict' => false,                             // true = 取不到密钥时抛异常中断启动（删除明文后建议开启）
    'secrets' => [
        'mysql' => 'test-mysql8',                  // 简写：使用 AccountName / AccountPassword
        'redis' => [
            'secret_id' => 'test-redis',
            'include_username' => true,            // ACL 模式用；经典模式改 false
            // 'user_field' => 'AccountName',      // 可选，字段名不标准时覆盖
            // 'pass_field' => 'AccountPassword',
        ],
    ],
];
```

> 安装时插件会把默认配置拷入宿主项目的 `config/plugin/srako/kms/app.php`，直接编辑该文件即可；修改后 `php webman reload` 生效。kms 配置不再经 env.yaml / Nacos 下发（env.yaml 中如残留旧版 `kms:` 段已不生效，应清理）。

## 接入示例

```php
// config/database.php
$kmsMysql = kms_credentials('mysql');
'username' => $kmsMysql['username'] ?? yaml('database.mysql.username', ''),
'password' => $kmsMysql['password'] ?? yaml('database.mysql.password', ''),

// config/redis.php（ACL 模式；username 为空串时 illuminate 自动退回单参数 AUTH）
$kmsRedis = kms_credentials('redis');
'username' => $kmsRedis['username'] ?? yaml('redis.username', ''),
'password' => $kmsRedis['password'] ?? yaml('redis.password', null),

// config/plugin/webman/redis-queue/redis.php（workerman/redis 原生 client）
'auth' => kms_redis_auth($kmsRedis) ?? yaml('redis.password'),

// config/session.php（phpredis 直连，ACL 需关联数组）
'auth' => kms_redis_auth($kmsRedis) ?? yaml('redis.password'),
```

可用函数：

| 函数 | 说明 |
| --- | --- |
| `kms_credentials($alias)` | `['username' => ..., 'password' => ...]`；未启用/未配置/失败时 `null` |
| `kms_secret($secretId, $fresh = false)` | 原始 SecretData 数组（供其它用途复用） |
| `kms_enabled()` | `config/plugin/srako/kms/app.php` 中 `enable === true` |
| `kms_redis_auth($creds)` | ACL → `['user'=>..., 'pass'=>...]`；经典 → 纯密码串；无凭据 → `null` |

## 命令

```bash
php webman kms:check                        # 各 alias 的来源/版本/年龄（密码只显示长度与 sha1 前 8 位）
php webman kms:check --fresh                # 绕过进程内缓存，强制直连代理拉取
php webman kms:check --test-connections     # 附加数据库 SELECT 1 与 Redis PING 测试
php webman kms:check --json                 # 机器可读输出
```

退出码：`0` 正常（含未启用）；`1` 已启用但未配置 secrets；`2` 拉取失败；`3` 连接测试失败。

## 解析链与回退语义

```
内存缓存(TTL 内) → HTTP 拉取 → null（回退明文；strict=true 时抛异常）
```

- 拉取失败后有 `fail_cooldown`（默认 30s）负缓存，避免启动期反复请求挂起的代理
- 凭据不落盘：没有文件缓存、没有 `--warm`；进程重启后首次使用即直连代理解析
- `strict: true`：已启用但取不到时报错中断启动（默认 false 保持韧性；从 env.yaml 删除明文后建议开启）

## 密钥轮换监控

插件自带 `RotationMonitor` 进程（独立进程 count=1，`reloadable=false`）：

- 每 `monitor_interval` 秒（默认 60s）直连代理比对各 secretId 的版本指纹（VersionId）
- 检测到轮换、或代理从"不可用"恢复 → 向 master 发送 `SIGUSR1` 触发 webman 优雅 reload，各 worker 重新加载配置拿到新凭据
- 监控进程不随 reload 重启（保留基线），不会重复触发；`monitor_interval: 0` 关闭监控（轮换后需手动 `php webman reload`）

### 从 env.yaml 明文迁移到 KMS 的建议顺序

1. 宿主 `app.php` 配好 `enable` + `secrets`（alias → secretId），`php webman kms:check` 全绿
2. 删除 env.yaml（含 Nacos 侧内容）中对应明文密码，`php webman kms:check --test-connections` 复验
3. 开启 `strict: true`：此后代理不可用时启动直接失败，而不是静默使用空凭据

## 升级注意（v0.1.1 → v0.1.2）

- 移除文件缓存（`runtime/kms/*.json`）：无需再关注该目录；`kms:check --warm` 选项已删除
- 新增轮换监控进程：`composer update srako/webman-kms` 会自动拷入 `config/plugin/srako/kms/process.php`
- 旧版曾在 env.yaml 配置 `kms:` 段（v0.1.1 起已失效），请从 env.yaml / Nacos 中清理
