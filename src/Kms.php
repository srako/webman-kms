<?php

namespace Srako\WebmanKms;

use Srako\WebmanKms\Support\Logger;

/**
 * KMS 门面。
 *
 * 配置来源：config/plugin/srako/kms/app.php（安装时由插件拷入宿主项目）。`enable`
 * 为总开关（默认 false，同时是 webman 插件加载门控）；未启用时所有调用直接返回
 * null，调用方（config 文件）以 `??` 回退到 env.yaml 明文，本地开发零影响。
 *
 * 解析链：内存缓存(TTL 内) -> 文件缓存(未过期) -> HTTP 拉取 -> 过期文件缓存(告警) -> null。
 */
class Kms
{
    private static ?array $config = null;
    private static ?Client $client = null;
    private static ?SecretCache $cache = null;

    /** @var array<string, array{data: array, version_id: ?string, source: string, fetched_at: int}> */
    private static array $memory = [];

    /** @var array<string, int> secretId => failed_at */
    private static array $negative = [];

    /** @var array<string, int> secretId => last warn time */
    private static array $lastWarn = [];

    public static function config(): array
    {
        if (static::$config !== null) {
            return static::$config;
        }

        $app = [];
        if (function_exists('config')) {
            try {
                $loaded = \config('plugin.srako.kms.app');
                if (is_array($loaded)) {
                    $app = $loaded;
                }
            } catch (\Throwable) {
                $app = [];
            }
        }
        if (!$app && function_exists('config_path')) {
            try {
                $file = config_path('plugin/srako/kms/app.php');
                if (is_string($file) && is_file($file)) {
                    $loaded = require $file;
                    $app = is_array($loaded) ? $loaded : [];
                }
            } catch (\Throwable) {
                $app = [];
            }
        }
        if (!$app) {
            $file = __DIR__ . '/config/plugin/srako/kms/app.php';
            $loaded = is_file($file) ? require $file : [];
            $app = is_array($loaded) ? $loaded : [];
        }

        $app['enable'] = ($app['enable'] ?? false) === true;
        static::$config = $app;
        static::$client = null;
        static::$cache = null;

        return static::$config;
    }

    public static function enabled(): bool
    {
        return (static::config()['enable'] ?? false) === true;
    }

    public static function secretId(string $alias): ?string
    {
        $entry = static::normalizeSecret(static::config()['secrets'][$alias] ?? null);
        return $entry['secret_id'] ?? null;
    }

    /**
     * 凭据（alias 由 app.php 的 secrets 配置）。
     *
     * @return array{username: string, password: string}|null
     */
    public static function credentials(string $alias): ?array
    {
        if (!static::enabled()) {
            return null;
        }
        $entry = static::normalizeSecret(static::config()['secrets'][$alias] ?? null);
        if ($entry === null) {
            return null;
        }
        $resolved = static::resolve($entry['secret_id']);
        if ($resolved === null) {
            return null;
        }

        $password = $resolved['data'][$entry['pass_field']] ?? null;
        if (!is_string($password) || $password === '') {
            static::warn($entry['secret_id'], 'kms secret password field is empty', ['field' => $entry['pass_field']]);
            return null;
        }

        $username = '';
        if ($entry['include_username']) {
            $value = $resolved['data'][$entry['user_field']] ?? '';
            $username = is_string($value) ? $value : '';
        }

        return ['username' => $username, 'password' => $password];
    }

    /**
     * 原始 SecretData 数组（按 secretId，供后续其它用途复用）。
     */
    public static function secret(string $secretId, bool $fresh = false): ?array
    {
        if (!static::enabled()) {
            return null;
        }
        $resolved = static::resolve($secretId, $fresh);
        return $resolved['data'] ?? null;
    }

    /**
     * 诊断信息（kms:check 使用；绝不包含明文密码）。
     */
    public static function diagnose(string $aliasOrSecretId, bool $fresh = false): array
    {
        $config = static::config();
        $result = [
            'input' => $aliasOrSecretId,
            'secret_id' => null,
            'source' => 'disabled',
            'version_id' => null,
            'age' => null,
            'username' => '',
            'password_len' => 0,
            'password_sha1' => null,
            'cache_path' => null,
        ];
        if (($config['enable'] ?? false) !== true) {
            return $result;
        }

        $entry = static::normalizeSecret($config['secrets'][$aliasOrSecretId] ?? null);
        if ($entry === null) {
            // 直接传了 secretId：按默认字段检查
            $entry = [
                'secret_id' => $aliasOrSecretId,
                'include_username' => true,
                'user_field' => (string)($config['user_field'] ?? 'AccountName'),
                'pass_field' => (string)($config['pass_field'] ?? 'AccountPassword'),
            ];
        }
        $result['secret_id'] = $entry['secret_id'];
        $result['cache_path'] = static::cache()->path($entry['secret_id']);

        $resolved = static::resolve($entry['secret_id'], $fresh);
        if ($resolved === null) {
            $result['source'] = 'unavailable';
            return $result;
        }

        $result['source'] = $resolved['source'];
        $result['version_id'] = $resolved['version_id'];
        $result['age'] = max(0, time() - $resolved['fetched_at']);

        $password = $resolved['data'][$entry['pass_field']] ?? null;
        if ($entry['include_username']) {
            $value = $resolved['data'][$entry['user_field']] ?? '';
            $result['username'] = is_string($value) ? $value : '';
        }
        if (is_string($password) && $password !== '') {
            $result['password_len'] = strlen($password);
            $result['password_sha1'] = substr(sha1($password), 0, 8);
        }

        return $result;
    }

    public static function flush(): void
    {
        static::$config = null;
        static::$client = null;
        static::$cache = null;
        static::$memory = [];
        static::$negative = [];
        static::$lastWarn = [];
    }

    /**
     * @return array{secret_id: string, include_username: bool, user_field: string, pass_field: string}|null
     */
    private static function normalizeSecret(mixed $raw): ?array
    {
        $config = static::config();
        $defaults = [
            'include_username' => true,
            'user_field' => (string)($config['user_field'] ?? 'AccountName'),
            'pass_field' => (string)($config['pass_field'] ?? 'AccountPassword'),
        ];
        if (is_string($raw) && $raw !== '') {
            return ['secret_id' => $raw] + $defaults;
        }
        if (is_array($raw) && is_string($raw['secret_id'] ?? null) && $raw['secret_id'] !== '') {
            return array_replace($defaults, $raw);
        }
        return null;
    }

    /**
     * @return array{data: array, version_id: ?string, source: string, fetched_at: int}|null
     */
    private static function resolve(string $secretId, bool $fresh = false): ?array
    {
        $config = static::config();
        $ttl = max(0, (int)($config['cache_ttl'] ?? 3600));

        if (!$fresh) {
            $memory = static::$memory[$secretId] ?? null;
            if ($memory !== null && time() - $memory['fetched_at'] <= $ttl) {
                return $memory;
            }
        }

        if (!$fresh) {
            $cooldown = max(0, (int)($config['fail_cooldown'] ?? 30));
            $failedAt = static::$negative[$secretId] ?? null;
            if ($failedAt !== null && time() - $failedAt < $cooldown) {
                return static::fromStaleCache($secretId);
            }

            $cached = static::cache()->get($secretId);
            if ($cached !== null) {
                return static::remember($secretId, $cached['data'], $cached['version_id'], 'file', $cached['fetched_at']);
            }
        }

        $fetched = static::client()->fetch($secretId);
        if ($fetched !== null) {
            static::cache()->put($secretId, $fetched['version_id'], $fetched['data']);
            unset(static::$negative[$secretId]);
            return static::remember($secretId, $fetched['data'], $fetched['version_id'], 'fresh', time());
        }

        static::$negative[$secretId] = time();
        $stale = static::fromStaleCache($secretId);
        if ($stale !== null) {
            static::warn($secretId, 'kms agent unavailable, falling back to stale cache');
            return $stale;
        }

        static::warn($secretId, 'kms secret unavailable and no cached copy');
        if (($config['strict'] ?? false) === true) {
            throw new \RuntimeException("webman-kms: unable to fetch secret [{$secretId}] and no cache available");
        }
        return null;
    }

    /**
     * @return array{data: array, version_id: ?string, source: string, fetched_at: int}|null
     */
    private static function fromStaleCache(string $secretId): ?array
    {
        $cached = static::cache()->getStale($secretId);
        if ($cached === null) {
            return null;
        }
        return static::remember($secretId, $cached['data'], $cached['version_id'], 'stale', $cached['fetched_at']);
    }

    /**
     * @return array{data: array, version_id: ?string, source: string, fetched_at: int}
     */
    private static function remember(string $secretId, array $data, ?string $versionId, string $source, int $fetchedAt): array
    {
        return static::$memory[$secretId] = [
            'data' => $data,
            'version_id' => $versionId,
            'source' => $source,
            'fetched_at' => $fetchedAt,
        ];
    }

    private static function client(): Client
    {
        return static::$client ??= new Client(static::config());
    }

    private static function cache(): SecretCache
    {
        return static::$cache ??= new SecretCache(max(0, (int)(static::config()['cache_ttl'] ?? 3600)));
    }

    private static function warn(string $secretId, string $message, array $context = []): void
    {
        $now = time();
        if ($now - (static::$lastWarn[$secretId] ?? 0) < 60) {
            return;
        }
        static::$lastWarn[$secretId] = $now;
        Logger::warning($message, ['secret' => $secretId] + $context);
    }
}
