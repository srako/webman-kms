<?php

namespace Srako\WebmanKms\Console;

use Srako\WebmanKms\Kms;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class KmsCheckCommand extends Command
{
    protected static $defaultName = 'kms:check';

    protected static $defaultDescription = 'Check KMS agent connectivity, secrets and connections';

    protected function configure(): void
    {
        $this->addOption('secret', 's', InputOption::VALUE_REQUIRED, 'Only check the given alias or secretId');
        $this->addOption('fresh', null, InputOption::VALUE_NONE, 'Bypass process memory cache and fetch from the agent');
        $this->addOption('test-connections', null, InputOption::VALUE_NONE, 'Test database / redis connections with resolved credentials');
        $this->addOption('json', null, InputOption::VALUE_NONE, 'Output as JSON');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $json = (bool)$input->getOption('json');
        $fresh = (bool)$input->getOption('fresh');
        $testConnections = (bool)$input->getOption('test-connections');
        $only = (string)($input->getOption('secret') ?? '');

        if (!Kms::enabled()) {
            if ($json) {
                $output->writeln(json_encode([
                    'enabled' => false,
                    'message' => 'kms disabled (`enable` is not true in config/plugin/srako/kms/app.php); plaintext fallback is in effect',
                ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            } else {
                $output->writeln('<comment>kms disabled (`enable` is not true in config/plugin/srako/kms/app.php); plaintext fallback is in effect</comment>');
            }
            return self::SUCCESS;
        }

        $config = Kms::config();
        $secrets = array_keys($config['secrets'] ?? []);

        if ($only !== '') {
            $targets = [$only];
        } elseif ($secrets === []) {
            $output->writeln('<error>kms enabled but no `secrets` configured in config/plugin/srako/kms/app.php</error>');
            return 1;
        } else {
            $targets = $secrets;
        }

        $endpoint = (string)($config['endpoint'] ?? '');
        $tokenFile = (string)($config['token_file'] ?? '');

        $checks = [];
        $exitCode = self::SUCCESS;
        foreach ($targets as $target) {
            $row = Kms::diagnose($target, $fresh);
            $checks[] = $row;
            // unavailable = 拉取失败（无落盘兜底），自检/部署门禁必须视为失败
            if ($row['source'] === 'unavailable') {
                $exitCode = max($exitCode, 2);
            }
        }

        $monitorInterval = (int)($config['monitor_interval'] ?? 60);

        $connections = [];
        if ($testConnections) {
            foreach ($this->testConnections() as $label => $result) {
                $connections[$label] = $result;
                if (!$result['ok']) {
                    $exitCode = max($exitCode, 3);
                }
            }
        }

        if ($json) {
            $output->writeln(json_encode([
                'enabled' => true,
                'endpoint' => $endpoint,
                'token_file' => $tokenFile,
                'token_readable' => $tokenFile !== '' && is_readable($tokenFile),
                'monitor_interval' => $monitorInterval,
                'checks' => $checks,
                'connections' => $connections,
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
            return $exitCode;
        }

        $output->writeln('endpoint: ' . $endpoint);
        $output->writeln(sprintf('token_file: %s (%s)', $tokenFile, ($tokenFile !== '' && is_readable($tokenFile)) ? 'readable' : 'NOT readable'));
        $output->writeln($monitorInterval > 0
            ? "rotation monitor: every {$monitorInterval}s (auto reload on rotation/recovery)"
            : 'rotation monitor: disabled (rotation requires manual `php webman reload`)');

        $table = new Table($output);
        $table->setHeaders(['alias', 'secret_id', 'source', 'version_id', 'age(s)', 'username', 'password']);
        foreach ($checks as $row) {
            $password = $row['password_len'] > 0
                ? sprintf('len=%d sha1=%s', $row['password_len'], $row['password_sha1'])
                : '-';
            $table->addRow([
                $row['input'],
                $row['secret_id'] ?? '-',
                $row['source'],
                $row['version_id'] ?? '-',
                $row['age'] ?? '-',
                $row['username'] !== '' ? $row['username'] : '-',
                $password,
            ]);
        }
        $table->render();

        foreach ($connections as $label => $result) {
            $output->writeln(($result['ok'] ? '<info>[ok]  </info>' : '<error>[fail]</error>') . " {$label}: {$result['message']}");
        }

        return $exitCode;
    }

    /**
     * @return array<string, array{ok: bool, message: string}>
     */
    private function testConnections(): array
    {
        $results = [];

        foreach ((array)config('database.connections', []) as $name => $conf) {
            if (!is_array($conf)) {
                continue;
            }
            $driver = (string)($conf['driver'] ?? '');
            if (!in_array($driver, ['mysql', 'pgsql'], true)) {
                continue;
            }
            $label = "db:{$name}";
            try {
                $dsn = sprintf(
                    '%s:host=%s;port=%s;dbname=%s',
                    $driver,
                    (string)($conf['host'] ?? ''),
                    (string)($conf['port'] ?? '3306'),
                    (string)($conf['database'] ?? '')
                );
                $pdo = new \PDO(
                    $dsn,
                    (string)($conf['username'] ?? ''),
                    (string)($conf['password'] ?? ''),
                    [\PDO::ATTR_TIMEOUT => 3, \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]
                );
                $pdo->query('SELECT 1');
                $results[$label] = ['ok' => true, 'message' => 'SELECT 1 ok'];
            } catch (\Throwable $e) {
                $results[$label] = ['ok' => false, 'message' => $e->getMessage()];
            }
        }

        $redisConf = config('redis.default', []);
        if (is_array($redisConf) && $redisConf !== []) {
            $label = 'redis:default';
            if (!class_exists(\Redis::class)) {
                $results[$label] = ['ok' => true, 'message' => 'phpredis extension not loaded, skipped'];
            } else {
                try {
                    $client = new \Redis();
                    $client->connect((string)($redisConf['host'] ?? ''), (int)($redisConf['port'] ?? 6379), 3.0);
                    $password = (string)($redisConf['password'] ?? '');
                    $username = (string)($redisConf['username'] ?? '');
                    if ($password !== '') {
                        if ($username !== '') {
                            $client->auth([$username, $password]);
                        } else {
                            $client->auth($password);
                        }
                    }
                    $client->ping();
                    $results[$label] = [
                        'ok' => true,
                        'message' => 'PING ok' . ($username !== '' ? " (acl user: {$username})" : ''),
                    ];
                } catch (\Throwable $e) {
                    $results[$label] = ['ok' => false, 'message' => $e->getMessage()];
                }
            }
        }

        return $results;
    }
}
