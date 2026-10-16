<?php
/**
 * 本地 KMS 代理 mock，用于开发机联调（服务器上不需要）。
 *
 * 用法：
 *   MOCK_SECRETS_FILE=/tmp/kms-mock-secrets.json \
 *   MOCK_TOKEN_FILE=/tmp/kmstoken \
 *   php -S 127.0.0.1:2025 examples/mock-kms-agent.php
 *
 * 秘密文件格式（参考 examples/mock-secrets.sample.json）：
 *   {"test-mysql8": {"AccountName": "web_user", "AccountPassword": "..."},
 *    "test-redis": {"AccountName": "user",     "AccountPassword": "..."}}
 *
 * 建议用本地 env.yaml 里的真实明文凭据生成该文件，这样 mock 链路之外的
 * 数据库/Redis 连接测试也能真实通过；该文件不要提交到仓库。
 */

$tokenFile = getenv('MOCK_TOKEN_FILE') ?: '/tmp/kmstoken';
$secretsFile = getenv('MOCK_SECRETS_FILE') ?: (__DIR__ . '/mock-secrets.json');
$secrets = is_file($secretsFile) ? (json_decode(file_get_contents($secretsFile), true) ?: []) : [];

header('Content-Type: application/json; charset=utf-8');

$token = trim($_SERVER['HTTP_X_KMS_TOKEN'] ?? '');
$expected = is_file($tokenFile) ? trim((string)file_get_contents($tokenFile)) : '';
if ($expected === '' || $token === '' || !hash_equals($expected, $token)) {
    http_response_code(403);
    echo json_encode(['Code' => 'Forbidden', 'Message' => 'invalid X-KMS-Token'], JSON_UNESCAPED_UNICODE);
    return;
}

$secretId = (string)($_GET['secretId'] ?? '');
if (!isset($secrets[$secretId])) {
    http_response_code(404);
    echo json_encode(['Code' => 'SecretNotFound', 'Message' => "unknown secretId [{$secretId}]"], JSON_UNESCAPED_UNICODE);
    return;
}

$data = $secrets[$secretId];
echo json_encode([
    'SecretName' => $secretId,
    'SecretType' => 'Rds',
    'SecretDataType' => 'text',
    'VersionId' => 'mock-' . substr(sha1(json_encode($data)), 0, 12),
    'VersionStages' => ['ACSCurrent'],
    'AutomaticRotation' => 'Enabled',
    'SecretData' => json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
