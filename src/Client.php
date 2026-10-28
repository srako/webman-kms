<?php

namespace Srako\WebmanKms;

use Srako\WebmanKms\Support\Logger;

/**
 * KMS 本地代理 HTTP 客户端。
 *
 * 协议：GET {endpoint}?secretId=<id>，请求头 X-KMS-Token 取自令牌文件；
 * 响应 JSON 的 SecretData 为 JSON 字符串（需二次 json_decode），字段示例：
 * {"AccountName":"user","AccountPassword":"..."}。
 */
class Client
{
    /**
     * 复用的 curl 句柄：轮换监控会高频轮询，复用句柄避免每次请求新建
     * CurlHandle / 连接对象（句柄级连接缓存在进程内是有界且可预期的）。
     *
     * @var \CurlHandle|null
     */
    private $handle = null;

    public function __construct(
        private readonly array $config
    ) {
    }

    /**
     * 拉取密钥原始数据。
     *
     * @return array{data: array, version_id: ?string, secret_name: ?string}|null
     */
    public function fetch(string $secretId): ?array
    {
        $token = $this->token();
        if ($token === null) {
            Logger::warning('kms token file missing, unreadable or empty', [
                'token_file' => (string)($this->config['token_file'] ?? ''),
            ]);
            return null;
        }

        $url = $this->buildUrl($secretId);
        if ($url === null) {
            Logger::warning('kms endpoint not configured');
            return null;
        }

        [$status, $body] = $this->request($url, $token);
        if ($status !== 200 || $body === null || $body === '') {
            Logger::warning('kms agent request failed', [
                'kms_id' => $secretId,
                'status' => $status,
                'body' => $body === null ? null : mb_substr($body, 0, 200),
            ]);
            return null;
        }

        $response = json_decode($body, true);
        if (!is_array($response)) {
            Logger::warning('kms agent response is not valid json', ['kms_id' => $secretId]);
            return null;
        }

        $data = $this->extractData($response['SecretData'] ?? null);
        if ($data === null) {
            Logger::warning('kms secret data missing or unresolvable', [
                'kms_id' => $secretId,
                'code' => isset($response['Code']) ? (string)$response['Code'] : null,
                'message' => isset($response['Message']) ? mb_substr((string)$response['Message'], 0, 200) : null,
            ]);
            return null;
        }

        return [
            'data' => $data,
            'version_id' => isset($response['VersionId']) ? (string)$response['VersionId'] : null,
            'secret_name' => isset($response['SecretName']) ? (string)$response['SecretName'] : null,
        ];
    }

    private function extractData(mixed $secretData): ?array
    {
        if (is_array($secretData)) {
            return $secretData;
        }
        if (!is_string($secretData) || $secretData === '') {
            return null;
        }
        $decoded = json_decode($secretData, true);
        return is_array($decoded) ? $decoded : null;
    }

    private function token(): ?string
    {
        $file = (string)($this->config['token_file'] ?? '');
        if ($file === '' || !is_file($file) || !is_readable($file)) {
            return null;
        }
        $token = @file_get_contents($file);
        if ($token === false) {
            return null;
        }
        $token = trim($token);
        return $token === '' ? null : $token;
    }

    private function buildUrl(string $secretId): ?string
    {
        $endpoint = (string)($this->config['endpoint'] ?? '');
        if ($endpoint === '') {
            return null;
        }
        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . 'secretId=' . rawurlencode($secretId);
    }

    /**
     * 非协程上下文（CLI / 插件进程）复用同一句柄，避免轮询场景反复新建
     * CurlHandle；协程上下文（Swoole/Swow/native curl hook）并发时会串用
     * 同一 easy handle，必须按请求新建。
     */
    private function curlHandle(): \CurlHandle
    {
        if (static::inCoroutine()) {
            return curl_init();
        }
        return $this->handle ??= curl_init();
    }

    private static function inCoroutine(): bool
    {
        try {
            if (class_exists(\Swoole\Coroutine::class, false) && \Swoole\Coroutine::getCid() > 0) {
                return true;
            }
            if (class_exists(\Workerman\Coroutine::class, false) && \Workerman\Coroutine::isCoroutine()) {
                return true;
            }
        } catch (\Throwable) {
            // 运行时探测失败时按非协程处理（保底走句柄复用）
        }
        return false;
    }

    /**
     * @return array{0: int, 1: ?string}
     */
    private function request(string $url, string $token): array
    {
        $timeout = max(1, (int)($this->config['timeout'] ?? 3));

        // 优先 curl：不受 swoole hook 影响，worker 启动/协程内调用都安全。
        // 全程复用同一个句柄（curl_reset 重置后重设全部选项），轮询场景下
        // 不再按请求创建 CurlHandle / 连接对象。
        if (function_exists('curl_init')) {
            $ch = $this->curlHandle();
            curl_reset($ch);
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_CONNECTTIMEOUT => min(2, $timeout),
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_HTTPHEADER => ['X-KMS-Token: ' . $token],
            ]);
            $body = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $error = curl_error($ch);
            if ($body === false) {
                Logger::warning('kms agent curl error', ['error' => $error]);
                return [0, null];
            }
            return [$status, (string)$body];
        }

        // 无 curl 扩展时的 stream 兜底
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $timeout,
                'header' => "X-KMS-Token: {$token}\r\n",
                'ignore_errors' => true,
            ],
        ]);
        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            Logger::warning('kms agent stream request failed');
            return [0, null];
        }
        $status = 0;
        // $http_response_header 自 PHP 8.5 废弃，8.4+ 用新函数；本包仍兼容 8.2。
        $headers = function_exists('http_get_last_response_headers')
            ? (http_get_last_response_headers() ?? [])
            : ($http_response_header ?? []);
        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $m)) {
                $status = (int)$m[1];
            }
        }
        return [$status, $body];
    }
}
