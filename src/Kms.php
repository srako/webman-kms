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
 * 解析链：进程内内存缓存(TTL 内) -> HTTP 拉取 -> null（strict=true 时抛异常）。
 * 凭据不落盘；密钥轮换由 RotationMonitor 进程检测并触发 webman 优雅 reload。
 */
class Kms
{
    private static ?array $config = null;

    /** 建立 $config 缓存时的进程号：fork 出的 worker 与 master 不一致即重读 */
    private static ?int $configPid = null;

    /** true = 跳过 webman Config 快照，直接 require app.php（常驻进程感知变更用） */
    private static bool $readFromFile = false;

    private static ?Client $client = null;

    /** @var array<string, array{data: array, version_id: ?string, source: string, fetched_at: int}> */
    private static array $memory = [];

    /**
     * fork 时从父进程继承的最后一次成功凭据：不直接使用（可能已是轮换前的旧值），
     * 仅在 Agent 不可用时（非 strict）兜底，成功拉取后即丢弃。
     *
     * @var array<string, array{data: array, version_id: ?string, source: string, fetched_at: int}>
     */
    private static array $inherited = [];

    /** @var array<string, int> secretId => failed_at */
    private static array $negative = [];

    /** @var array<string, int> secretId => last warn time */
    private static array $lastWarn = [];

    public static function config(): array
    {
        $pid = static::pid();
        if (static::$config !== null && static::$configPid === $pid) {
            return static::$config;
        }

        if (static::$config !== null) {
            // master 在 App::run() 预热过配置与凭据，fork 出的 worker 继承的是旧内存：
            // 不清掉就会继续用旧 app.php 的 secret_id / 旧密码（Reload 等于没生效）。
            // 旧凭据留作 Agent 不可用时的兜底（见 resolve），成功拉取后即丢弃。
            foreach (static::$memory as $id => $entry) {
                static::$inherited[$id] = ['source' => 'inherited'] + $entry;
            }
            static::$memory = [];
            static::$negative = [];
            static::$lastWarn = [];
        }

        $app = [];
        if (!static::$readFromFile && function_exists('config')) {
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
        static::$configPid = $pid;
        static::$client = null;

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
     * 已配置的全部 secretId（去重；供轮换监控等使用）。
     *
     * @return array<int, string>
     */
    public static function secretIds(): array
    {
        $ids = [];
        foreach ((array)(static::config()['secrets'] ?? []) as $raw) {
            $entry = static::normalizeSecret($raw);
            if ($entry !== null) {
                $ids[$entry['secret_id']] = true;
            }
        }
        return array_keys($ids);
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
     * 版本指纹：直连代理拉取（不读写内存缓存），返回 VersionId；代理未返回时
     * 退化为 SecretData 的 sha1。失败返回 null（Client 已告警）。
     */
    public static function fingerprint(string $secretId): ?string
    {
        if (!static::enabled()) {
            return null;
        }
        $fetched = static::client()->fetch($secretId);
        if ($fetched === null) {
            return null;
        }
        return $fetched['version_id'] ?? 'sha1:' . sha1(serialize($fetched['data']));
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
        ];
        if (($config['enable'] ?? false) !== true) {
            return $result;
        }

        $entry = static::normalizeSecret($config['secrets'][$aliasOrSecretId] ?? null);
        if ($entry === null) {
            if ($aliasOrSecretId !== '' && array_key_exists($aliasOrSecretId, (array)($config['secrets'] ?? []))) {
                // alias 已配置但未解析出 secret_id（如 env.yaml 缺 key）：配置问题
                $result['source'] = 'unconfigured';
                return $result;
            }
            // 直接传了 secretId：按默认字段检查
            $entry = [
                'secret_id' => $aliasOrSecretId,
                'include_username' => true,
                'user_field' => (string)($config['user_field'] ?? 'AccountName'),
                'pass_field' => (string)($config['pass_field'] ?? 'AccountPassword'),
            ];
        }
        $result['secret_id'] = $entry['secret_id'];

        try {
            $resolved = static::resolve($entry['secret_id'], $fresh);
        } catch (\RuntimeException) {
            // 诊断接口不抛异常：strict 模式下同样以 unavailable 呈现
            $resolved = null;
        }
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
        static::$configPid = null;
        static::$readFromFile = false;
        static::$client = null;
        static::$memory = [];
        static::$inherited = [];
        static::$negative = [];
        static::$lastWarn = [];
    }

    /**
     * 丢弃配置缓存，下次调用时直接 require app.php 重读。
     *
     * 供不随 reload 重启的常驻进程（rotation_monitor）感知 secret_id 切换：这类
     * 进程的 webman Config 快照停留在启动时刻，只读 `config()` 拿不到新值。
     * 同时丢弃 Client，下一轮按新的 endpoint / token_file 重建；worker 侧仍需
     * reload/restart 才会重读配置。
     */
    public static function reloadConfig(): void
    {
        static::$config = null;
        static::$configPid = null;
        static::$client = null;
        static::$readFromFile = true;
    }

    private static function pid(): ?int
    {
        if (function_exists('posix_getpid')) {
            return posix_getpid();
        }
        if (function_exists('getmypid')) {
            $pid = getmypid();
            return $pid === false ? null : $pid;
        }
        return null;
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

            $cooldown = max(0, (int)($config['fail_cooldown'] ?? 30));
            $failedAt = static::$negative[$secretId] ?? null;
            if ($failedAt !== null && time() - $failedAt < $cooldown) {
                // 近期拉取失败（已告警过）：冷却期内不重试；恢复由轮换监控触发 reload
                if (($config['strict'] ?? false) === true) {
                    throw new \RuntimeException("webman-kms: unable to fetch secret [{$secretId}] (in fail cooldown)");
                }
                return static::$inherited[$secretId] ?? null;
            }
        }

        $fetched = static::client()->fetch($secretId);
        if ($fetched !== null) {
            unset(static::$negative[$secretId], static::$inherited[$secretId]);
            return static::remember($secretId, $fetched['data'], $fetched['version_id'], 'fresh', time());
        }

        static::$negative[$secretId] = time();
        $fallback = !$fresh && ($config['strict'] ?? false) !== true ? (static::$inherited[$secretId] ?? null) : null;
        if ($fallback !== null) {
            // Agent 不可用：非 strict 下沿用父进程的最后一次成功凭据，避免 reload 撞上
            // Agent 抖动时拿不到密码 / 回退明文；成功拉取后即换成新值。
            static::warn($secretId, 'kms secret unavailable, using inherited credentials from parent process', [
                'stale_age' => max(0, time() - $fallback['fetched_at']),
            ]);
            return $fallback;
        }
        static::warn($secretId, 'kms secret unavailable (agent unreachable or secret not found)');
        if (($config['strict'] ?? false) === true) {
            throw new \RuntimeException("webman-kms: unable to fetch secret [{$secretId}]");
        }
        return null;
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

    private static function warn(string $secretId, string $message, array $context = []): void
    {
        $now = time();
        if ($now - (static::$lastWarn[$secretId] ?? 0) < 60) {
            return;
        }
        static::$lastWarn[$secretId] = $now;
        Logger::warning($message, ['kms_id' => $secretId] + $context);
    }
}
