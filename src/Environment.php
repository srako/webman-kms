<?php

namespace Srako\WebmanKms;

use Symfony\Component\Yaml\Yaml;

/**
 * 读取宿主项目的 env.yaml。
 *
 * 不依赖项目的 yaml() 函数（不同项目实现不一），按 mtime+size 失效缓存；
 * 解析失败（如 Nacos 覆盖写入过程中的半成品）保留上一次成功结果，避免把配置读空。
 */
class Environment
{
    private static array $cache = [];

    public static function filePath(): string
    {
        if (function_exists('base_path')) {
            try {
                $path = base_path('env.yaml');
                if (is_string($path) && $path !== '') {
                    return $path;
                }
            } catch (\Throwable) {
                // ignore
            }
        }
        $cwd = getcwd();
        return ($cwd === false ? '.' : $cwd) . '/env.yaml';
    }

    public static function signature(): string
    {
        $path = static::filePath();
        clearstatcache(true, $path);
        $mtime = @filemtime($path);
        if ($mtime === false) {
            return 'missing';
        }
        return $mtime . ':' . (@filesize($path) ?: 0);
    }

    public static function all(): array
    {
        $path = static::filePath();
        $signature = static::signature();
        $cached = static::$cache[$path] ?? null;
        if ($cached !== null && $cached['signature'] === $signature) {
            return $cached['data'];
        }

        if ($signature === 'missing') {
            return static::$cache[$path]['data'] ?? [];
        }

        $raw = @file_get_contents($path);
        if ($raw === false || $raw === '') {
            return $cached['data'] ?? [];
        }

        try {
            $data = Yaml::parse($raw);
        } catch (\Throwable) {
            return $cached['data'] ?? [];
        }
        if (!is_array($data)) {
            $data = [];
        }

        static::$cache[$path] = ['signature' => $signature, 'data' => $data];
        return $data;
    }

    public static function section(string $key, mixed $default = null): mixed
    {
        $all = static::all();
        return array_key_exists($key, $all) ? $all[$key] : $default;
    }

    public static function reset(): void
    {
        static::$cache = [];
    }
}
