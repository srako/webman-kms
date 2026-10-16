<?php

return [
    // 密钥轮换监控：独立进程（count=1）；reloadable=false 使其不随自身触发的
    // reload 重启，保留版本基线，避免重复触发。开关见 app.php 的 monitor_interval。
    'rotation_monitor' => [
        'handler' => \Srako\WebmanKms\Process\RotationMonitor::class,
        'count' => 1,
        'reloadable' => false,
    ],
];
