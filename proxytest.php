<?php
// HTTP proxy implementation with PHP socket
// Go Namhyeon <gnh1201@gmail.com>
// 2022-10-06

ini_set("default_socket_timeout", 1);

$data = json_decode(file_get_contents('php://input'), true);

$buffer_size = $data['chunksize'];

$port = intval($data['port']);
$hostname = $data['server'];
// TODO: HTTPS support
/*
if ($port == 443) {
    $hostname = "ssl://" . $hostname;
}
*/

$fp = fsockopen($hostname, $port, $errno, $errstr, 1);

if (!$fp) {
    echo "$errstr ($errno)<br />\n";
} else {
    $out = base64_decode($data['data']);
    fwrite($fp, $out);

    $buf = null;
    while (!feof($fp) && $buf !== false) {
        $buf = fgets($fp, $buffer_size);
        echo $buf;
    }

    fclose($fp);
}
