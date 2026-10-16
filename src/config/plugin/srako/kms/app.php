<?php

return [
    // 总开关（同时是 webman 插件加载门控）：false 时本插件配置与 kms:check
    // 命令都不会加载，所有调用直接返回 null（调用方回退 env.yaml 明文）。
    'enable' => false,

    // KMS 本地代理地址
    'endpoint' => 'http://localhost:2025/secretsmanager/get',

    // X-KMS-Token 令牌文件
    'token_file' => '/var/run/kmstoken',

    // 单次请求超时（秒）
    'timeout' => 3,

    // 文件缓存有效期（秒）；仅影响新启动进程对新值的感知，轮换后需 reload
    'cache_ttl' => 3600,

    // 拉取失败后的进程内负缓存时长（秒），避免启动期反复请求挂起的代理
    'fail_cooldown' => 30,

    // true = KMS 已启用但取不到且无缓存时抛异常中断（严格模式）；
    // false = 记录告警并返回 null，调用方回退 env.yaml 明文
    'strict' => false,

    // SecretData 中的用户名字段 / 密码字段
    'user_field' => 'AccountName',
    'pass_field' => 'AccountPassword',

    // alias => secretId 或 ['secret_id' => ..., 'include_username' => false, 'user_field' => ..., 'pass_field' => ...]
    // 按环境不同的映射直接写在本文件；示例：
    // 'mysql' => 'test-mysql8',
    // 'redis' => ['secret_id' => 'test-redis', 'include_username' => true],
    'secrets' => [],
];
