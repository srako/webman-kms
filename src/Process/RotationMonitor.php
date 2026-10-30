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
 * 拿到新凭据。`reloadable=false`：自身不随 reload 重启，保留基线避免重复触发；
 * 因此每轮重读 app.php（Kms::reloadConfig），secret_id 切换后无需重启本进程。
 *
 * 自愈：连续多轮全部拉取失败、或打开 fd 数相对基线异常增长时主动退出，由
 * webman master 重新拉起一个干净进程（兜底潜在资源泄漏，不依赖具体泄漏点）。
 */
class RotationMonitor
{
    private const FAILURE_LIMIT = 10;

    private const FD_GROWTH_LIMIT = 50;

    /** @var array<string, ?string> secretId => 版本指纹（null = 上次拉取失败） */
    private array $fingerprints = [];

    private int $consecutiveFailures = 0;

    /** @var int 首次采样到的 fd 数；0 = 尚未采样 */
    private int $baselineFds = 0;

    private bool $idleWarned = false;

    public function onWorkerStart(): void
    {
        if (!Kms::enabled()) {
            return;
        }
        $interval = (int)(Kms::config()['monitor_interval'] ?? 60);
        if ($interval <= 0) {
            return;
        }
        // 启动即建立基线（首次不触发 reload）；此后每轮重读配置
        $this->poll();
        Timer::add($interval, function (): void {
            $this->poll();
        });
    }

    private function poll(): void
    {
        // 本进程 reloadable=false，reload 后不会重启：每轮重读 app.php，
        // 否则 secret_id 切换后监控仍按启动时的快照轮询旧密钥。
        Kms::reloadConfig();
        if (!Kms::enabled()) {
            return;
        }
        $secretIds = Kms::secretIds();
        if ($secretIds === []) {
            if (!$this->idleWarned) {
                $this->idleWarned = true;
                Logger::warning('kms rotation monitor idle: no resolvable secret ids in `secrets` config');
            }
            return;
        }
        $this->idleWarned = false;
        // 配置里已删除的 secretId 不再轮询，避免之后重新加回时按旧指纹误触发 reload
        $this->fingerprints = array_intersect_key($this->fingerprints, array_flip($secretIds));

        $rotated = [];
        $recovered = [];
        $failures = 0;
        foreach ($secretIds as $secretId) {
            $current = Kms::fingerprint($secretId);
            if ($current === null) {
                $failures++;
            }
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

        $this->consecutiveFailures = $failures === count($secretIds) ? $this->consecutiveFailures + 1 : 0;
        $this->checkSelfHeal();

        if ($rotated === [] && $recovered === []) {
            return;
        }
        Logger::warning('kms secret rotated, reloading webman to apply new credentials', [
            'rotated' => $rotated,
            'recovered' => $recovered,
        ]);
        static::reload();
    }

    private function checkSelfHeal(): void
    {
        if ($this->consecutiveFailures >= self::FAILURE_LIMIT) {
            $this->recycle(sprintf('%d consecutive poll failures', $this->consecutiveFailures));
        }
        $count = static::openFds();
        if ($count === null) {
            return;
        }
        if ($this->baselineFds === 0) {
            $this->baselineFds = $count;
            return;
        }
        if ($count > $this->baselineFds + self::FD_GROWTH_LIMIT) {
            $this->recycle(sprintf('open fd %d exceeds baseline %d + %d', $count, $this->baselineFds, self::FD_GROWTH_LIMIT));
        }
    }

    /**
     * @return int|null 打开 fd 数；非 Linux（无 /proc）时返回 null
     */
    private static function openFds(): ?int
    {
        if (DIRECTORY_SEPARATOR !== '/' || !is_dir('/proc/self/fd')) {
            return null;
        }
        $fds = @scandir('/proc/self/fd');
        return is_array($fds) ? count($fds) - 2 : null;
    }

    /**
     * 主动退出，由 webman master 重新 fork 一个干净的监控进程。
     */
    private function recycle(string $reason): void
    {
        Logger::warning('kms rotation monitor self-heal: exiting for a fresh worker process', ['reason' => $reason]);
        exit(1);
    }

    private static function reload(): void
    {
        if (DIRECTORY_SEPARATOR !== '/' || !function_exists('posix_kill')) {
            Logger::warning('kms rotation monitor: graceful reload not supported on this platform, please restart manually');
            return;
        }
        if (!posix_kill(posix_getppid(), SIGUSR1)) {
            Logger::warning('kms rotation monitor: failed to signal master for graceful reload');
        }
    }
}
