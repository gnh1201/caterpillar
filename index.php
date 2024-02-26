<?php
// Caterpillar - The simple and parasitic web proxy with spam filter
// Namhyeon Go (Catswords Research) <abuse@catswords.net>
// https://github.com/gnh1201/caterpillar
// Created at: 2022-10-06
// Updated at: 2024-02-26

define("PHP_HTTPPROXY_VERSION", "0.2.0-dev");

if (strpos($_SERVER['HTTP_USER_AGENT'], "php-httpproxy/") !== 0) {
    exit('<!DOCTYPE html><html><head><title>It works!</title><meta charset="utf-8"></head><body><h1>It works!</h1><p><a href="https://github.com/gnh1201/caterpillar">Download the client</a></p><hr><p>php-httpproxy/' . PHP_HTTPPROXY_VERSION . ' (Server; PHP ' . phpversion() . '; abuse@catswords.net)</p></body></html>');
}

ini_set("default_socket_timeout", 1);  // must be. because of `feof()` works
ini_set("max_execution_time", 0);

function jsonrpc2_encode($method, $params, $id = '') {
    $data = array(
        "jsonrpc" => "2.0",
        "method" => $method,
        "params" => $params,
        "id" => $id
    );
    return json_encode($data);
}

function jsonrpc2_result_encode($result, $id = '') {
    $data = array(
        "jsonrpc" => "2.0",
        "result" => $result,
        "id" => $id
    );
    return json_encode($data);
}

function jsonrpc2_error_encode($error, $id = '') {
    $data = array(
        "jsonrpc" => "2.0",
        "error" => $error,
        "id" => $id
    );
    return json_encode($data);
}

function parse_headers($str) { // Parses HTTP headers into an array
    // https://stackoverflow.com/questions/16934409/curl-as-proxy-deal-with-https-connect-method
    // https://stackoverflow.com/questions/12433958/how-to-parse-response-headers-in-php
    $headers = array();

    $lines = preg_split("'\r?\n'", $str);

    $first_line = array_shift($lines);
    $headers['@method'] = explode(' ', $first_line);

    foreach ($lines as $line) {
        if (!preg_match('/^([^:]+):(.*)$/', $line, $out)) continue;
        $headers[$out[1]] = trim($out[2]);
    }

    return $headers;
}

function read_from_remote_server($remote_address, $remote_port, $scheme, $data = null, $conn = null, $buffer_size = 8192, $id = '') {
    if (in_array($scheme, array("https", "ssl", "tls"))) {
        $remote_address = "tls://" . $remote_address;
    }

    $sock = fsockopen($remote_address, $remote_port, $error_code, $error_message, 1);
    if (!$sock) {
        $error = array(
            "status" => 502,
            "code" => $error_code,
            "message" => $error_message
        );

        if ($conn == null) {
            echo jsonrpc2_error_encode($error, $id);
        } else {
            $buf = sprintf("HTTP/1.1 502 Bad Gateway\r\n\r\n");
            $buf .= jsonrpc2_error_encode($error, $id);
            fwrite($conn, $buf);
        }
    } else {
        if ($conn == null) {
            // send data
            fwrite($sock, $data);

            // receive data
            $buf = null;
            while (!feof($sock) && $buf !== false) {
                $buf = fgets($sock, $buffer_size);
                echo $buf;
            }
        } else {
            // send data
            $buf = null;
            while (!feof($conn) && $buf !== false) {
                $buf = fgets($conn, $buffer_size);
                fwrite($sock, $buf);
            }

            // receive data
            $buf = null;
            while (!feof($sock) && $buf !== false) {
                $buf = fgets($sock, $buffer_size);
                fwrite($conn, $buf);
            }
        }

        fclose($sock);
    }
}

// stateless mode
function relay_request($params, $id = '') {
    $buffer_size = $params['buffer_size'];
    $request_data = base64_decode($params['request_data']);
    $request_header = parse_headers($request_data);
    $request_length = intval($params['request_length']);
    $client_address = $params['client_address'];
    $client_port = intval($params['client_port']);
    $client_encoding = $params['client_encoding'];
    $remote_address = $params['remote_address'];
    $remote_port = intval($params['remote_port']);
    $scheme = $params['scheme'];
    $datetime = $params['datetime'];   // format: %Y-%m-%d %H:%M:%S.%f

    if (in_array($scheme, array("https", "ssl", "tls"))) {
        $remote_address = "tls://" . $remote_address;
    }

    switch ($request_header['@method'][0]) {
        case "CONNECT":
            $error = array(
                "status" => 405,
                "code" => -1,
                "message" => "Method Not Allowed"
            );
            echo jsonrpc2_error_encode($error, $id);
            break;

        default:
            read_from_remote_server($remote_address, $remote_port, $scheme, $request_data, null, $buffer_size, $id);
    }
}

// stateful mode
function relay_connect($params, $id = '') {
    $buffer_size = $params['buffer_size'];
    $client_address = $params['client_address'];
    $client_port = intval($params['client_port']);
    $client_encoding = $params['client_encoding'];
    $remote_address = $params['remote_address'];
    $remote_port = intval($params['remote_port']);
    $scheme = $params['scheme'];
    $datetime = $params['datetime'];   // format: %Y-%m-%d %H:%M:%S.%f

    $conn = fsockopen($client_address, $client_port, $error_code, $error_message, 1);
    if (!$conn) {
        $error = array(
            "status" => 502,
            "code" => $error_code,
            "message" => $error_message,
            "_params" => $params
        );
        echo jsonrpc2_error_encode($error, $id);
    } else {
        $data = jsonrpc2_encode("relay_accept", array(
            "success" => true
        ), $id);
        fwrite($conn, $data . "\r\n\r\n");

        read_from_remote_server($remote_address, $remote_port, $scheme, null, $conn, $buffer_size, $id);
        fclose($conn);
    }
}

function get_client_address() {
    $client_address = '';
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $client_address = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $client_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $client_address = $_SERVER['REMOTE_ADDR'];
    }
    return array("client_address" => $client_address);
}

// parse context
$context = json_decode(file_get_contents('php://input'), true);

// check is it jsonrpc
if ($context['jsonrpc'] == "2.0") {
    $method = $context['method'];
    switch ($method) {
        case "relay_request":
            relay_request($context['params'], $context['id']);    // stateless mode
            break;

        case "relay_connect":
            relay_connect($context['params'], $context['id']);    // stateful mode
            break;

        case "get_client_address":
            echo jsonrpc2_result_encode(get_client_address(), $context['id']);
            break;
    }
}
