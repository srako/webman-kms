<?php

namespace Srako\WebmanKms\Process;

use Srako\WebmanKms\Kms;
use Srako\WebmanKms\Support\Logger;
use Workerman\Timer;

/**
 * 密钥轮换监控进程（插件自带，count=1）。
 *
 * 周期性直连本地代理比对各 secretId 的版本指纹；检测到轮换（或代理从不可用
 * 恢复）时向 master 发送 SIGUSR1 触发优雅 reload，使各 worker 重新加载配置、
 * 拿到新凭据。`reloadable=false`：自身不随 reload 重启，保留基线避免重复触发。
 */
class RotationMonitor
{
    /** @var array<string, ?string> secretId => 版本指纹（null = 上次拉取失败） */
    private array $fingerprints = [];

    public function onWorkerStart(): void
    {
        if (!Kms::enabled()) {
            return;
        }
        $interval = (int)(Kms::config()['monitor_interval'] ?? 60);
        if ($interval <= 0) {
            return;
        }
        $secretIds = Kms::secretIds();
        if ($secretIds === []) {
            return;
        }
        // 启动即建立基线（首次不触发 reload）
        $this->poll($secretIds);
        Timer::add($interval, function () use ($secretIds): void {
            $this->poll($secretIds);
        });
    }

    /**
     * @param array<int, string> $secretIds
     */
    private function poll(array $secretIds): void
    {
        $rotated = [];
        $recovered = [];
        foreach ($secretIds as $secretId) {
            $current = Kms::fingerprint($secretId);
            if (!array_key_exists($secretId, $this->fingerprints)) {
                $this->fingerprints[$secretId] = $current;
                continue;
            }
            $previous = $this->fingerprints[$secretId];
            $this->fingerprints[$secretId] = $current;
            if ($current === null) {
                continue;
            }
            if ($previous === null) {
                $recovered[] = $secretId;
            } elseif ($previous !== $current) {
                $rotated[] = $secretId;
            }
        }
        if ($rotated === [] && $recovered === []) {
            return;
        }
        Logger::warning('kms secret rotated, reloading webman to apply new credentials', [
            'rotated' => $rotated,
            'recovered' => $recovered,
        ]);
        static::reload();
    }

    private static function reload(): void
    {
        if (DIRECTORY_SEPARATOR !== '/' || !function_exists('posix_kill')) {
            Logger::warning('kms rotation monitor: graceful reload not supported on this platform, please restart manually');
            return;
        }
        posix_kill(posix_getppid(), SIGUSR1);
    }
}
