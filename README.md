# srako/webman-kms

Webman 通用 composer 包：从**阿里云 KMS 本地代理（sidecar）**获取数据库/Redis 凭据，替代 env.yaml 明文。

- 本地代理协议：`GET http://localhost:2025/secretsmanager/get?secretId=<id>`，请求头 `X-KMS-Token` 取自 `/var/run/kmstoken`
- 内存 + 文件双层缓存（`runtime/kms/*.json`，目录 0700 / 文件 0600）
- 未启用 / 拉取失败时返回 `null`，调用方以 `??` 回退 env.yaml 明文，**本地开发零影响**
- 自带 `php webman kms:check` 自检命令（连通性 / 密钥 / 缓存 / 数据库与 Redis 连接测试）
- 不打印任何明文密码与 token；缓存文件与 env.yaml 明文本同级（0600）

## 安装

```bash
composer require srako/webman-kms
```

安装时 webman 插件机制会把 `config/plugin/srako/kms/{app.php,command.php}` 拷入项目。

## 配置（config/plugin/srako/kms/app.php）

```php
return [
    'enable' => true,                              // 总开关；false = 全部回退 env.yaml 明文
    'endpoint' => 'http://localhost:2025/secretsmanager/get',
    'token_file' => '/var/run/kmstoken',
    'timeout' => 3,
    'cache_ttl' => 3600,
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

> 安装时插件会把默认配置拷入宿主项目的 `config/plugin/srako/kms/app.php`，直接编辑该文件即可；修改后 `php webman reload` 生效。kms 配置不再经 env.yaml / Nacos 下发。

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
php webman kms:check --fresh                # 强制直连代理拉取
php webman kms:check --test-connections     # 附加数据库 SELECT 1 与 Redis PING 测试
php webman kms:check --warm                 # 预热并落盘缓存（部署脚本用）
php webman kms:check --json                 # 机器可读输出
```

退出码：`0` 正常；`1` 已启用但未配置 secrets；`2` 拉取失败、stale 降级或缓存目录不可写；`3` 连接测试失败。

## 解析链与回退语义

```
内存缓存(TTL 内) → 文件缓存(未过期) → HTTP 拉取 → 过期文件缓存(告警) → null(回退明文；strict=true 时抛异常)
```

- 拉取失败后有 `fail_cooldown`（默认 30s）负缓存，避免启动期反复请求挂起的代理
- `strict: true`：已启用但取不到且无缓存时抛异常中断启动（默认 false，保持韧性）
- **轮换感知**：配置仅在进程启动时加载一次；KMS 轮换后需 `php webman reload`。可选 cron 定时 `php webman kms:check --warm` 保持缓存热

