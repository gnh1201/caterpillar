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

function jsonrpc2_encode($params) {
    $data = array(
        "jsonrpc" => "2.0",
        "params" => $params
    );
    return json_encode($data);
}

function jsonrpc2_result_encode($result) {
    $data = array(
        "jsonrpc" => "2.0",
        "result" => $result
    );
    return json_encode($data);
}

function jsonrpc2_error_encode($error) {
    $data = array(
        "jsonrpc" => "2.0",
        "error" => $error
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

// stateless mode
function relay_request($params) {
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
    $url = $params['url'];
    $datetime = $params['datetime'];   // format: %Y-%m-%d %H:%M:%S.%f

    if (in_array($scheme, array("https", "ssl", "tls"))) {
        $remote_address = "tls://" . $remote_address;
    }

    switch ($request_header['@method'][0]) {
        case "CONNECT":
            echo sprintf("%s 200 Connection Established\r\n\r\n", $request_header['@method'][2]);
            break;

        default:
            $fp = fsockopen($remote_address, $remote_port, $error_code, $error_message, 1);
            if (!$fp) {
                $error = array(
                    "status" => 400,
                    "code" => $error_code,
                    "message" => $error_message
                );
                echo "HTTP/1.1 400 Bad Request\r\n\r\n" . jsonrpc2_error_encode($error);
            } else {
                fwrite($fp, $request_data);

                $buf = null;
                while (!feof($fp) && $buf !== false) {
                    $buf = fgets($fp, $buffer_size);
                    echo $buf;
                }

                fclose($fp);
            }
    }
}

// stateful mode
function relay_connect($params) {
    $buffer_size = $params['buffer_size'];
    $client_address = $params['client_address'];
    $client_port = intval($params['client_port']);
    $client_encoding = $params['client_encoding'];
    $remote_address = $params['remote_address'];
    $remote_port = intval($params['remote_port']);
    $scheme = $params['scheme'];
    $url = $params['url'];
    $datetime = $params['datetime'];   // format: %Y-%m-%d %H:%M:%S.%f

    $fp = fsockopen($client_address, $client_port, $error_code, $error_message, 1);
    if (!$fp) {
        $error = array(
            "status" => 400,
            "code" => $error_code,
            "message" => $error_message
        );
        echo "HTTP/1.1 400 Bad Request\r\n\r\n" . jsonrpc2_error_encode($error);
    } else {
        fwrite($fp, jsonrpc2_result_encode(array("success" => true)));

        $buf = null;
        while (!feof($fp) && $buf !== false) {
            $buf = fgets($fp, $buffer_size);
            // todo
        }
        
        fclose($fp);
    }
}

// parse context
$context = json_decode(file_get_contents('php://input'), true);

// check is it jsonrpc
if ($context['jsonrpc'] == "2.0") {
    $method = $context['method'];
    switch ($method) {
        case "relay_request":
            relay_request($context['params']);    // stateless mode
            break;
        case "relay_connect":
            relay_connect($context['params']);    // stateful mode
            break;
    }
}
