<?php

namespace Srako\WebmanKms;

/**
 * 文件缓存：runtime/kms/<sanitized-secret-id>.json。
 * 目录 0700、文件 0600，tmp+rename 原子写；缓存内含明文密码（与 env.yaml 明文本同级）。
 */
class SecretCache
{
    private ?string $dir = null;

    public function __construct(
        private readonly int $ttl
    ) {
    }

    public function dir(): string
    {
        if ($this->dir !== null) {
            return $this->dir;
        }

        $dir = null;
        if (function_exists('runtime_path')) {
            try {
                $dir = runtime_path('kms');
            } catch (\Throwable) {
                $dir = null;
            }
        }
        if (!$dir) {
            $base = function_exists('base_path') ? base_path() : (getcwd() ?: '.');
            $dir = $base . '/runtime/kms';
        }
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
            @chmod($dir, 0700);
        }
        return $this->dir = $dir;
    }

    public function path(string $secretId): string
    {
        return $this->dir() . '/' . static::fileName($secretId);
    }

    /**
     * 未过期缓存。
     *
     * @return array{secret_id: string, version_id: ?string, fetched_at: int, data: array}|null
     */
    public function get(string $secretId): ?array
    {
        $entry = $this->read($secretId);
        if ($entry === null || time() - $entry['fetched_at'] > $this->ttl) {
            return null;
        }
        return $entry;
    }

    /**
     * 兜底缓存（agent 不可用时使用，不限过期）。
     *
     * @return array{secret_id: string, version_id: ?string, fetched_at: int, data: array}|null
     */
    public function getStale(string $secretId): ?array
    {
        return $this->read($secretId);
    }

    public function put(string $secretId, ?string $versionId, array $data): void
    {
        $file = $this->path($secretId);
        $payload = json_encode([
            'secret_id' => $secretId,
            'version_id' => $versionId,
            'fetched_at' => time(),
            'data' => $data,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($payload === false) {
            return;
        }

        $tmp = $file . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, $payload) === false) {
            return;
        }
        @chmod($tmp, 0600);
        @rename($tmp, $file);
    }

    private function read(string $secretId): ?array
    {
        $raw = @file_get_contents($this->path($secretId));
        if ($raw === false || $raw === '') {
            return null;
        }
        $entry = json_decode($raw, true);
        if (!is_array($entry)
            || ($entry['secret_id'] ?? null) !== $secretId
            || !is_array($entry['data'] ?? null)
            || !isset($entry['fetched_at'])) {
            return null;
        }
        return [
            'secret_id' => (string)$entry['secret_id'],
            'version_id' => isset($entry['version_id']) ? (string)$entry['version_id'] : null,
            'fetched_at' => (int)$entry['fetched_at'],
            'data' => $entry['data'],
        ];
    }

    private static function fileName(string $secretId): string
    {
        return preg_replace('/[^A-Za-z0-9._-]/', '_', $secretId) . '.json';
    }
}
