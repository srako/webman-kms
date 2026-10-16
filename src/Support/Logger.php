<?php

namespace Srako\WebmanKms\Support;

/**
 * 安全日志：优先 webman 的 support\Log，失败回退 error_log；对上下文键名做脱敏。
 * 配置加载早期（support\Log 尚不可用）也不会抛异常。
 */
class Logger
{
    private const PREFIX = '[webman-kms] ';

    public static function warning(string $message, array $context = []): void
    {
        static::log('warning', $message, $context);
    }

    public static function error(string $message, array $context = []): void
    {
        static::log('error', $message, $context);
    }

    private static function log(string $level, string $message, array $context = []): void
    {
        $line = static::PREFIX . $message;
        if ($context !== []) {
            $line .= ' ' . json_encode(static::sanitize($context), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        if (class_exists(\support\Log::class)) {
            try {
                \support\Log::{$level}($line);
                return;
            } catch (\Throwable) {
                // 配置尚未加载完成等场景，退回 error_log
            }
        }
        error_log($line);
    }

    private static function sanitize(array $context): array
    {
        foreach ($context as $key => $value) {
            // 只脱敏凭据类键；secret id 保留（排查需要，本身不是敏感值）
            if (is_string($key) && preg_match('/pass|token|auth|credential|pwd/i', $key)) {
                $context[$key] = '***';
            } elseif (is_array($value)) {
                $context[$key] = static::sanitize($value);
            }
        }
        return $context;
    }
}
