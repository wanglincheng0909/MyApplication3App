<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');

$db_file = 'access_logs.db';

try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 获取查询参数
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 100;
    $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
    $order = isset($_GET['order']) && $_GET['order'] === 'asc' ? 'ASC' : 'DESC';
    
    // 获取统计数据
    $stats = [];
    
    // 总访问次数
    $stmt = $pdo->query("SELECT COUNT(*) as total FROM access_logs");
    $stats['total'] = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
    
    // 今日访问次数
    $stmt = $pdo->query("SELECT COUNT(*) as today FROM access_logs WHERE DATE(timestamp) = DATE('now')");
    $stats['today'] = $stmt->fetch(PDO::FETCH_ASSOC)['today'];
    
    // 独立IP数量
    $stmt = $pdo->query("SELECT COUNT(DISTINCT ip_address) as unique_ips FROM access_logs");
    $stats['unique_ips'] = $stmt->fetch(PDO::FETCH_ASSOC)['unique_ips'];
    
    // 平均响应时间
    $stmt = $pdo->query("SELECT AVG(response_time) as avg_response_time FROM access_logs WHERE response_time > 0");
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $stats['avg_response_time'] = $result['avg_response_time'] ? round($result['avg_response_time']) : 0;
    
    // 获取访问日志
    $sql = "SELECT 
                id,
                timestamp,
                ip_address,
                user_agent,
                device_type,
                platform,
                app_version,
                device_model,
                request_method,
                request_uri,
                country,
                city,
                isp,
                response_time,
                status_code,
                request_headers
            FROM access_logs 
            ORDER BY timestamp $order 
            LIMIT $limit OFFSET $offset";
    
    $stmt = $pdo->query($sql);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // 处理日志数据
    foreach ($logs as &$log) {
        // 解析User-Agent获取更多设备信息
        $log['parsed_ua'] = parseUserAgent($log['user_agent']);
        
        // 格式化时间戳
        $log['formatted_time'] = date('Y-m-d H:i:s', strtotime($log['timestamp']));
        
        // 解析请求头
        if ($log['request_headers']) {
            $log['headers'] = json_decode($log['request_headers'], true);
        }
    }
    
    // 获取最近24小时的访问趋势
    $trend_sql = "SELECT 
                    strftime('%H', timestamp) as hour,
                    COUNT(*) as count
                  FROM access_logs 
                  WHERE timestamp >= datetime('now', '-24 hours')
                  GROUP BY strftime('%H', timestamp)
                  ORDER BY hour";
    
    $stmt = $pdo->query($trend_sql);
    $hourly_trend = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // 获取设备类型统计
    $device_sql = "SELECT 
                     COALESCE(device_type, 'Unknown') as device_type,
                     COUNT(*) as count
                   FROM access_logs 
                   GROUP BY device_type
                   ORDER BY count DESC";
    
    $stmt = $pdo->query($device_sql);
    $device_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // 获取地理位置统计
    $location_sql = "SELECT 
                       COALESCE(country, 'Unknown') as country,
                       COUNT(*) as count
                     FROM access_logs 
                     GROUP BY country
                     ORDER BY count DESC
                     LIMIT 10";
    
    $stmt = $pdo->query($location_sql);
    $location_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // 返回结果
    echo json_encode([
        'success' => true,
        'stats' => $stats,
        'logs' => $logs,
        'trends' => [
            'hourly' => $hourly_trend,
            'devices' => $device_stats,
            'locations' => $location_stats
        ],
        'pagination' => [
            'limit' => $limit,
            'offset' => $offset,
            'total' => $stats['total']
        ]
    ], JSON_UNESCAPED_UNICODE);
    
} catch(PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}

// 解析User-Agent字符串
function parseUserAgent($userAgent) {
    $info = [
        'browser' => 'Unknown',
        'version' => 'Unknown',
        'os' => 'Unknown',
        'device' => 'Unknown'
    ];
    
    // 检测浏览器
    if (preg_match('/Chrome\/([0-9.]+)/', $userAgent, $matches)) {
        $info['browser'] = 'Chrome';
        $info['version'] = $matches[1];
    } elseif (preg_match('/Firefox\/([0-9.]+)/', $userAgent, $matches)) {
        $info['browser'] = 'Firefox';
        $info['version'] = $matches[1];
    } elseif (preg_match('/Safari\/([0-9.]+)/', $userAgent, $matches)) {
        $info['browser'] = 'Safari';
        $info['version'] = $matches[1];
    } elseif (preg_match('/MyApplication3\/([0-9.]+)/', $userAgent, $matches)) {
        $info['browser'] = 'MyApplication3';
        $info['version'] = $matches[1];
    }
    
    // 检测操作系统
    if (preg_match('/Windows NT ([0-9.]+)/', $userAgent, $matches)) {
        $info['os'] = 'Windows ' . getWindowsVersion($matches[1]);
    } elseif (preg_match('/Mac OS X ([0-9_]+)/', $userAgent, $matches)) {
        $info['os'] = 'macOS ' . str_replace('_', '.', $matches[1]);
    } elseif (preg_match('/Android ([0-9.]+)/', $userAgent, $matches)) {
        $info['os'] = 'Android ' . $matches[1];
    } elseif (preg_match('/iPhone OS ([0-9_]+)/', $userAgent, $matches)) {
        $info['os'] = 'iOS ' . str_replace('_', '.', $matches[1]);
    } elseif (strpos($userAgent, 'Linux') !== false) {
        $info['os'] = 'Linux';
    }
    
    // 检测设备
    if (preg_match('/\(([^)]+)\)/', $userAgent, $matches)) {
        $deviceInfo = $matches[1];
        if (preg_match('/(iPhone|iPad|iPod)/', $deviceInfo, $deviceMatches)) {
            $info['device'] = $deviceMatches[1];
        } elseif (preg_match('/([A-Z]{2,}-[A-Z0-9]+|SM-[A-Z0-9]+|Pixel [0-9]+)/', $deviceInfo, $deviceMatches)) {
            $info['device'] = $deviceMatches[1];
        }
    }
    
    return $info;
}

// 获取Windows版本名称
function getWindowsVersion($version) {
    $versions = [
        '10.0' => '10',
        '6.3' => '8.1',
        '6.2' => '8',
        '6.1' => '7',
        '6.0' => 'Vista',
        '5.1' => 'XP'
    ];
    
    return $versions[$version] ?? $version;
}
?>
