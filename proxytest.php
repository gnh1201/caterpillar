<?php
// HTTP proxy implementation with PHP socket
// Namhyeon Go <gnh1201@gmail.com>
// 2022-10-06

ini_set("default_socket_timeout", 1);  // must be. because of `feof()` works

$data = json_decode(file_get_contents('php://input'), true);

$buffer_size = $data['chunksize'];
$out = base64_decode($data['data']);

$port = intval($data['port']);
$scheme = $data['scheme'];

$hostname = $data['server'];
if ($scheme == "https") {
    $hostname = sprintf("tls://%s:%s", $hostname, $port);
}
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
