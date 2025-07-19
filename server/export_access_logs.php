<?php
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="access_logs_' . date('Y-m-d_H-i-s') . '.csv"');
header('Access-Control-Allow-Origin: *');

$db_file = 'access_logs.db';

try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 查询所有访问记录
    $sql = "SELECT 
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
                status_code
            FROM access_logs 
            ORDER BY timestamp DESC";
    
    $stmt = $pdo->query($sql);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // 输出CSV头部
    $output = fopen('php://output', 'w');
    
    // 添加BOM以支持中文
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    
    // CSV列标题
    $headers = [
        '访问时间',
        'IP地址',
        'User Agent',
        '设备类型',
        '平台',
        '应用版本',
        '设备型号',
        '请求方法',
        '请求URI',
        '国家',
        '城市',
        'ISP',
        '响应时间(ms)',
        '状态码'
    ];
    
    fputcsv($output, $headers);
    
    // 输出数据行
    foreach ($logs as $log) {
        $row = [
            $log['timestamp'],
            $log['ip_address'],
            $log['user_agent'],
            $log['device_type'] ?: '未知',
            $log['platform'] ?: '未知',
            $log['app_version'] ?: '未知',
            $log['device_model'] ?: '未知',
            $log['request_method'],
            $log['request_uri'],
            $log['country'] ?: '未知',
            $log['city'] ?: '未知',
            $log['isp'] ?: '未知',
            $log['response_time'] ?: 0,
            $log['status_code'] ?: 200
        ];
        
        fputcsv($output, $row);
    }
    
    fclose($output);
    
} catch(PDOException $e) {
    http_response_code(500);
    echo "导出失败: " . $e->getMessage();
}
?>
