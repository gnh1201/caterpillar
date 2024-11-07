<?php
/* index.php
 * Caterpillar Worker on PHP
 *
 * Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
 * Namhyeon Go (Catswords Research) <abuse@catswords.net>
 * https://github.com/gnh1201/caterpillar
 * Created at: 2022-10-06
 * Updated at: 2024-11-08
 */

define("PHP_HTTPPROXY_VERSION", "0.1.6.3-dev");
define("DEFAULT_SOCKET_TIMEOUT", 1);
define("STATEFUL_SOCKET_TIMEOUT", 30);
define("MAX_EXECUTION_TIME", 0);
define("DEFAULT_USER_AGENT", $_SERVER['HTTP_USER_AGENT'] . '</p><hr><p>php-httpproxy/' . PHP_HTTPPROXY_VERSION . ' (Server; PHP ' . phpversion() . '; Caterpillar; abuse@catswords.net)');

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: *');
header("Access-Control-Allow-Headers: *");

if (strpos($_SERVER['HTTP_USER_AGENT'], "php-httpproxy/") !== 0 && strpos($_SERVER['HTTP_X_USER_AGENT'], "php-httpproxy/") !== 0) {
    exit('<!DOCTYPE html><html><head><title>It works!</title><meta charset="utf-8"></head><body><h1>It works!</h1><p><a href="https://github.com/gnh1201/caterpillar">Download the client</a></p><p>' . DEFAULT_USER_AGENT . '</p></body></html>');
}

ini_set("default_socket_timeout", DEFAULT_SOCKET_TIMEOUT);  // must be. because of `feof()` works
ini_set("max_execution_time", MAX_EXECUTION_TIME);

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

// https://stackoverflow.com/questions/277224/how-do-i-catch-a-php-fatal-e-error-error
// https://stackoverflow.com/questions/3258634/php-how-to-send-http-response-code
function fatal_handler() {
    $errfile = "unknown file";
    $errstr  = "shutdown";
    $errno   = E_CORE_ERROR;
    $errline = 0;

    $error = error_get_last();

    if($error !== NULL) {
        $errno   = $error["type"];
        $errfile = $error["file"];
        $errline = $error["line"];
        $errstr  = $error["message"];

        header("HTTP/1.1 200 OK");
        exit(jsonrpc2_error_encode(array(
            "status" => 503,
            "code" => $errno,
            "message"=> "Error occurred in file '$errfile' at line $errline: $errstr"
        )));
    }
}
register_shutdown_function("fatal_handler");

// https://stackoverflow.com/questions/16934409/curl-as-proxy-deal-with-https-connect-method
// https://stackoverflow.com/questions/12433958/how-to-parse-response-headers-in-php
function parse_headers($str) { // Parses HTTP headers into an array
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

    $sock = fsockopen($remote_address, $remote_port, $error_code, $error_message, DEFAULT_SOCKET_TIMEOUT);
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

    $starttime = microtime(true);
    $conn = fsockopen($client_address, $client_port, $error_code, $error_message, STATEFUL_SOCKET_TIMEOUT);
    if (!$conn) {
        $error = array(
            "status" => 502,
            "code" => $error_code,
            "message" => $error_message,
            "_params" => $params
        );
        echo jsonrpc2_error_encode($error, $id);
    } else {
        $stoptime = microtime(true);
        $connection_speed = floor(($stoptime - $starttime) * 1000);
        $data = jsonrpc2_encode("relay_accept", array(
            "success" => true,
            "connection_speed" => $connection_speed
        ), $id);
        fwrite($conn, $data . "\r\n\r\n");

        read_from_remote_server($remote_address, $remote_port, $scheme, null, $conn, $buffer_size, $id);
        fclose($conn);
    }
}

function relay_mysql_connect($params) {
    $hostname = $params['hostname'];
    $username = $params['username'];
    $password = $params['password'];
    $database = array_key_exists('database', $params) ? $params['database'] : null;
    $port = array_key_exists('port', $params) ? intval($params['port']) : 3306;
    $charset = array_key_exists('charset', $params) ? $params['charset'] : "utf8";

    try {
        $mysqli = new mysqli($hostname, $username, $password, $database, $port);
        if ($mysqli->connect_errno) {
            return array(
                "success" => false,
                "error" => array(
                    "status" => 503,
                    "code" => $mysqli->connect_errno,
                    "message" => $mysqli->connect_error
                )
            );
        } else {
            $mysqli->set_charset($charset);
        }
    } catch (Exception $e) {
        return array(
            "success" => false,
            "error" => array(
                "status" => 503,
                "code" => -1,
                "message" => $e->__toString()
            )
        );
    }

    return array(
        "success" => true,
        "mysqli" => $mysqli,
        "result" => array(
            "status" => 200
        )
    );
}

function relay_mysql_query($params, $mysqli) {
    $query = trim($params['query']);
    $query_type = "";  // e.g., select, insert, update, delete
    $pos = strpos($query, ' ');
    if ($pos !== false) {
        $query_type = strtolower(substr($query, 0, $pos));
    }

    try {
        $query_result = $mysqli->query($query);

        if ($mysqli->error) {
            return array(
                "success" => false,
                "error" => array(
                    "status" => 503,
                    "code" => $msqli->errno,
                    "message" => $mysqli->error
                )
            );
        }

        $success = false;
        $result = array(
            "status" => 200
        );
        switch($query_type) {
            case "show":
            case "select":
                $success = true;
                if (function_exists("mysqli_fetch_all")) {
                    $result['data'] = mysqli_fetch_all($query_result, MYSQLI_ASSOC);
                } else {
                    $data = array();
                    while ($row = $query_result->fetch_assoc()) {
                        $data[] = $row;
                    }
                    $result['data'] = $data;
                }
                break;

            case "insert":
                $success = (bool) $query_result;
                $result['last_id'] = @$mysqli->insert_id;
                break;

            default:
                $success = (bool) $query_result;
        }

        return array(
            "success" => $success,
            "result" => $result
        );
    } catch (Exception $e) {
        return array(
            "success" => false,
            "error" => array(
                "status" => 503,
                "code" => -1,
                "message" => $e->__toString()
            )
        );
    }
}

function relay_sendmail($params) {
    $to      = $params['to'];
    $from    = $params['from'];
    $subject = $params['subject'];
    $message = $params['message'];
    $headers = 'From: ' . $from . "\r\n" .
        'X-Mailer: php-httpproxy/' . PHP_HTTPPROXY_VERSION . ' (Server; PHP ' . phpversion() . '; Caterpillar)';
    $sent = @mail($to, $subject, $message, $headers);
    if (!$sent) {
        $e = error_get_last();
        return array(
            "success" => false,
            "error" => array(
                "status" => 500,
                "code" => $e['type'],
                "message" => $e['message']
            )
        );
    }

    return array(
        "success" => true,
        "result" => array(
            "status" => 200
        )
    );
}

function relay_get_version() {
    return array(
        "data" => PHP_HTTPPROXY_VERSION
    );
}

function relay_get_phpversion() {
    return array(
        "data" => phpversion()
    );
}

function relay_get_loaded_extensions() {
    return array(
        "data" => get_loaded_extensions()
    );
}

function relay_dns_get_record($params) {
    $hostname = $params['hostname'];

    $data = dns_get_record($hostname);
    if (!$data) {
        return array(
            "success" => false,
            "error" => array(
                "status" => 502,
                "code" => -1,
                "message" => $hostname . " is not found in DNS records"
            )
        );
    }

    return array(
        "success" => true,
        "result" => array(
            "status" => 200,
            "data" => $data
        )
    );
}

function relay_fetch_url($params) {
    $url = $params['url'];

    try {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_USERAGENT, DEFAULT_USER_AGENT);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        $response = curl_exec($ch);
        $error_code = curl_errno($ch);
        if ($error_code) {
            $error_message = curl_error($ch);
            curl_close($ch);

            return array(
                "success" => false,
                "error" => array(
                    "status" => 502,
                    "code" => $error_code,
                    "message" => $error_message
                )
            );
        }
        curl_close($ch);

        return array(
            "success" => true,
            "result" => array(
                "status" => 200,
                "data" => $response
            )
        );
    } catch (Exception $e) {
        return array(
            "success" => false,
            "error" => array(
                "status" => 503,
                "code" => -1,
                "message" => $e->__toString()
            )
        );
    }
}

function relay_get_geolocation() {
    $result = relay_fetch_url(array(
        "url" => "http://ip-api.com/json"
    ));
    if ($result['success']) {
        return array(
            "success" => true,
            "result" => array(
                "status" => 200,
                "data" => json_decode($result['result']['data'], true)
            )
        );
    } else {
        return $result;
    }
}


function relay_invoke_method($params) {
    $callback = $params['callback'];
    $args = (is_array($params['args']) ? $params['args'] : array());

    try {
        $data = call_user_func_array($callback, $args);
        if ($data == null) {
            exit();   // Call to `fatal_handler` is delayed compared to the return.
        } else {
            return array(
                "success" => true,
                "result" => array(
                    "status" => 200,
                    "data" => $data
                )
            );
        }
    } catch (Exception $e) {
        return array(
            "success" => false,
            "error" => array(
                "status" => 503,
                "code" => -1,
                "message" => $e->__toString()
            )
        );
    }
}

function relay_web_search($params) {
    $page = $params['page'];
    $search_params = array(
        "q" => $params['keyword'],
        "p" => ($page > 0 ? $page - 1 : 0),
        "t" => "0"  // text only
    );
    $result = relay_fetch_url(array(
        "url" => "https://serp.catswords.net/api.php?" . http_build_query($search_params)
    ));
    if ($result['success']) {
        return array(
            "success" => true,
            "result" => array(
                "status" => 200,
                "data" => json_decode($result['result']['data'], true)
            )
        );
    } else {
        return $result;
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
    return array(
        "data" => $client_address,
        "client_address" => $client_address    // compatible under version 0.1.5.18
    );
}

// parse a context
$context = json_decode(file_get_contents('php://input'), true);

// check is it JSON-RPC 2 (stateless)
if ($context['jsonrpc'] == "2.0") {
    $method = $context['method'];
    switch ($method) {
        case "relay_request":
            relay_request($context['params'], $context['id']);    // stateless mode
            break;

        case "relay_connect":
            relay_connect($context['params'], $context['id']);    // stateful mode
            break;

        case "relay_mysql_query":
            $result = relay_mysql_connect($context['params']);
            if ($result['success']) {
                $mysqli = $result['mysqli'];
                $query_result = relay_mysql_query($context['params'], $mysqli);
                if ($query_result['success']) {
                    echo jsonrpc2_result_encode($query_result['result'], $context['id']);
                } else {
                    echo jsonrpc2_error_encode($query_result['error'], $context['id']);
                }
            } else {
                echo jsonrpc2_error_encode($result['error'], $context['id']);
            }
            break;

        case "relay_sendmail":
            $result = relay_sendmail($context['params']);
            if ($result['success']) {
                echo jsonrpc2_result_encode($result['result'], $context['id']);
            } else {
                echo jsonrpc2_error_encode($result['error'], $context['id']);
            }
            break;

        case "relay_get_version":
            echo jsonrpc2_result_encode(relay_get_version(), $context['id']);
            break;

        case "relay_get_phpversion":
            echo jsonrpc2_result_encode(relay_get_phpversion(), $context['id']);
            break;

        case "relay_get_loaded_extensions":
            echo jsonrpc2_result_encode(relay_get_loaded_extensions(), $context['id']);
            break;

        case "relay_dns_get_record":
            $result = relay_dns_get_record($context['params']);
            if ($result['success']) {
                echo jsonrpc2_result_encode($result['result'], $context['id']);
            } else {
                echo jsonrpc2_error_encode($result['error'], $context['id']);
            }
            break;

        case "relay_fetch_url":
            $result = relay_fetch_url($context['params']);
            if ($result['success']) {
                echo jsonrpc2_result_encode($result['result'], $context['id']);
            } else {
                echo jsonrpc2_error_encode($result['error'], $context['id']);
            }
            break;

        case "relay_get_geolocation":
            $result = relay_get_geolocation($context['params']);
            if ($result['success']) {
                echo jsonrpc2_result_encode($result['result'], $context['id']);
            } else {
                echo jsonrpc2_error_encode($result['error'], $context['id']);
            }
            break;

        case "relay_invoke_method":
            $result = relay_invoke_method($context['params']);
            if ($result['success']) {
                echo jsonrpc2_result_encode($result['result'], $context['id']);
            } else {
                echo jsonrpc2_error_encode($result['error'], $context['id']);
            }
            break;

        case "relay_web_search":
            $result = relay_web_search($context['params']);
            if ($result['success']) {
                echo jsonrpc2_result_encode($result['result'], $context['id']);
            } else {
                echo jsonrpc2_error_encode($result['error'], $context['id']);
            }
            break;

        case "get_client_address":
            echo jsonrpc2_result_encode(get_client_address(), $context['id']);
            break;

        default:
            echo jsonrpc2_error_encode(array(
                "status" => 403,
                "message" => "Unsupported method"
            ), $context['id']);
    }
} else {
    echo jsonrpc2_error_encode(array(
       "status" => 403,
       "message" => "Unsupported format"
    ), "");
}