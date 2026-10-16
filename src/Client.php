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
                'secret' => $secretId,
                'status' => $status,
                'body' => $body === null ? null : mb_substr($body, 0, 200),
            ]);
            return null;
        }

        $response = json_decode($body, true);
        if (!is_array($response)) {
            Logger::warning('kms agent response is not valid json', ['secret' => $secretId]);
            return null;
        }

        $data = $this->extractData($response['SecretData'] ?? null);
        if ($data === null) {
            Logger::warning('kms secret data missing or unresolvable', [
                'secret' => $secretId,
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
     * @return array{0: int, 1: ?string}
     */
    private function request(string $url, string $token): array
    {
        $timeout = max(1, (int)($this->config['timeout'] ?? 3));

        // 优先 curl：不受 swoole hook 影响，worker 启动/协程内调用都安全
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_CONNECTTIMEOUT => min(2, $timeout),
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_HTTPHEADER => ['X-KMS-Token: ' . $token],
            ]);
            $body = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $error = curl_error($ch);
            curl_close($ch);
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
        foreach ($http_response_header ?? [] as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $m)) {
                $status = (int)$m[1];
            }
        }
        return [$status, $body];
    }
}
