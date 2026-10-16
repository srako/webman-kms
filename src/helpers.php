<?php

use Srako\WebmanKms\Kms;

if (!function_exists('kms_enabled')) {
    /**
     * KMS 是否已启用（env.yaml 中 kms.enable === true）。
     */
    function kms_enabled(): bool
    {
        return Kms::enabled();
    }
}

if (!function_exists('kms_credentials')) {
    /**
     * 按 alias 取数据库/Redis 凭据，未启用或不可用时返回 null（调用方回退明文）。
     *
     * @return array{username: string, password: string}|null
     */
    function kms_credentials(string $alias): ?array
    {
        return Kms::credentials($alias);
    }
}

if (!function_exists('kms_secret')) {
    /**
     * 按 secretId 取原始 SecretData 数组；未启用或不可用时返回 null。
     */
    function kms_secret(string $secretId, bool $fresh = false): ?array
    {
        return Kms::secret($secretId, $fresh);
    }
}

if (!function_exists('kms_redis_auth')) {
    /**
     * 组装 redis auth 参数：
     * - ACL 模式（有 username）：['user' => ..., 'pass' => ...]（workerman/redis 会编码为 AUTH user pass，
     *   phpredis 直接支持该关联数组形式）
     * - 经典模式（无 username）：纯密码字符串（AUTH password）
     * - 无凭据：null
     *
     * @param array{username?: string, password?: string}|null $credentials
     */
    function kms_redis_auth(?array $credentials): string|array|null
    {
        if (!$credentials) {
            return null;
        }
        $password = (string)($credentials['password'] ?? '');
        if ($password === '') {
            return null;
        }
        $username = (string)($credentials['username'] ?? '');
        return $username !== '' ? ['user' => $username, 'pass' => $password] : $password;
    }
}
