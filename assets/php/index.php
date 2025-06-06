<?php
/* index.php
 * Caterpillar Proxy Worker on PHP runtime
 *
 * Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)
 * Namhyeon Go (Catswords Research) <abuse@catswords.net>
 * https://github.com/gnh1201/caterpillar
 * Created at: 2022-10-06
 * Updated at: 2025-03-11
 */
define("PERF_START_TIME", microtime(true));
define("PHP_HTTPPROXY_VERSION", "0.1.6.10");
define("DEFAULT_SOCKET_TIMEOUT", 1);
define("STATEFUL_SOCKET_TIMEOUT", 30);
define("MAX_EXECUTION_TIME", 0);
define("ALLOW_INVOKE_INSECURE_METHOD", false);
define("ALLOW_LOAD_INSECURE_SCRIPT", true);
define("DEFAULT_USER_AGENT", 'php-httpproxy/' . PHP_HTTPPROXY_VERSION . ' (Server; PHP ' . phpversion() . '; Caterpillar Proxy)');
define("RELAY_ALLOW_METHODS", "");  // e.g., GET,POST
define("RELAY_PROXY_PASS", "");  // e.g., https://example.org
define("RELAY_IMAGE_FILE_EXTENSIONS", ".png,.gif,.jpg");
define("RELAY_STATIC_FILE_EXTENSIONS", ".js,.css");
define("RELAY_ENABLE_JS_REDIRECT", false);

error_reporting(E_ALL);
ini_set("display_errors", 0);
ini_set("default_socket_timeout", DEFAULT_SOCKET_TIMEOUT);  // must be. because of `feof()` works
ini_set("max_execution_time", MAX_EXECUTION_TIME);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: *');
header("Access-Control-Allow-Headers: *");

function get_current_execution_time() {
    $end_time = microtime(true);
    return $end_time - PERF_START_TIME;
}

function array_get($key, $arr, $default = null) {
    return array_key_exists($key, $arr) ? $arr[$key] : $default;
}

function server_env_get($key) {
    return array_get($key, $_SERVER, "");
}

function verity_integrity($data, $integrity) {
    if (strpos($integrity, 'sha384-') !== 0) {
        return false;
    }
    
    $encoded_hash = substr($integrity, 7);
    $decoded_hash = base64_decode($encoded_hash);
    $calculated_hash = hash('sha384', $data, true);
    
    return hash_equals($calculated_hash, $decoded_hash);
}

function cast_to_array($data) {
    return is_array($data) ? $data : array($data);
}

function jsonrpc2_encode($method, $params, $id = '') {
    $data = array(
        "jsonrpc" => "2.0",
        "method" => $method,
        "params" => $params,
        "id" => $id,
        "_execution_time" => get_current_execution_time()
    );
    return json_encode($data);
}

function jsonrpc2_result_encode($result, $id = '') {
    $data = array(
        "jsonrpc" => "2.0",
        "result" => $result,
        "id" => $id,
        "_execution_time" => get_current_execution_time()
    );
    return json_encode($data);
}

function jsonrpc2_error_encode($error, $id = '') {
    $data = array(
        "jsonrpc" => "2.0",
        "error" => $error,
        "id" => $id,
        "_execution_time" => get_current_execution_time()
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
        exit("\r\n\r\n" . jsonrpc2_error_encode(array(
            "status" => 503,
            "code" => $errno,
            "message"=> "Error occurred in file '$errfile' at line $errline: $errstr"
        )));
    }
}
register_shutdown_function("fatal_handler");

function load_script($data) {
    $loaded_script = false;
    
    if (!ALLOW_LOAD_INSECURE_SCRIPT) {
        return $loaded_script;
    }

    $fh = tmpfile();
    if ($fh !== false) {
        if (!(strpos($data, "<?") !== false)) {
            $data = "<?php\r\n\r\n" . $data . "\r\n\r\n?>";
        }
        fwrite($fh, $data);
        $path = stream_get_meta_data($fh)['uri'];
        $loaded_script = include($path);
        fclose($fh);
    }

    return $loaded_script;
}

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
    $hostname = array_get("hostname", $params, "localhost");
    $username = array_get("username", $params, "root");
    $password = array_get("password", $params, "");
    $database = array_get("database", $params, null);
    $port = intval(array_get("port", $params, 3306));
    $charset = array_get("charset", $params, "utf8");

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

function relay_get_env_hash() {
    $params = array(
        "php_version" => phpversion(),
        "php_os" => PHP_OS,
        "php_sapi" => PHP_SAPI,
        "loaded_extensions" => get_loaded_extensions(),
        "ini_settings" => ini_get_all(null, false)
    );
    $serialized_params = serialize($params);

    return array(
        "data" => array(
            sha1($serialized_params),
            md5($serialized_params)
        )
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
    $method = array_get("method", $params, "GET");
    $headers = array_get("headers", $params, array());
    $data = array_get("data", $params, '');

    // from local source
    $local_prefix = "file:";
    $pos = strpos($url, $local_prefix);
    if ($pos !== false && $pos === 0) {
        $path = realpath(substr($url, strlen($local_prefix)));
        $basedir = realpath(__DIR__);
        
        if ($path && strpos($path, $basedir) === 0) {
            if (file_exists($path)) {
                $response = file_get_contents($path);
                return array(
                    "success" => true,
                    "result" => array(
                        "status" => 200,
                        "data" => $response
                    )
                );
            } else {
                return array(
                    "success" => false,
                    "error" => array(
                        "status" => 404,
                        "code" => -1,
                        "message" => "Not found"
                    )
                );
            }
        } else {
            return array(
                "success" => false,
                "error" => array(
                    "status" => 403,
                    "code" => -1,
                    "message" => "Access denied"
                )
            );
        }
    }

    // from remote source
    $_headers = array();
    if (is_array($headers) && count($headers) > 0) {
        foreach ($headers as $header_line) {
            $pos = strpos($header_line, ':');
            if ($pos !== false) {
                $header_key = trim(substr($header_line, 0, $pos));
                $header_value = trim(substr($header_line, $pos + 1));
                $_header_line = sprintf("%s: %s", $header_key, $header_value);
                array_push($_headers, $_header_line);
            }
        }
    }

    try {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_USERAGENT, DEFAULT_USER_AGENT);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_DNS_USE_GLOBAL_CACHE, false);
        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 30);
        
        // check the request headers
        if (count($_headers) > 0) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $_headers);
        }
        
        // check it is POST request
        if ($method == "POST") {
            curl_setopt($ch, CURLOPT_POSTFIELDS, cast_to_array($data));
            curl_setopt($ch, CURLOPT_POST, true);
        }

        // make cURL instance
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
    $requires = cast_to_array($params['requires']);
    $args = cast_to_array($params['args']);
    
    if (!ALLOW_INVOKE_INSECURE_METHOD) {
        $allow_callbacks = array("phpinfo", "idn_to_ascii", "idn_to_utf8", "load_script");
        if (!in_array($callback, $allow_callbacks)) {
            return array(
                "success" => false,
                "error" => array(
                    "status" => 403,
                    "code" => -1,
                    "message" => $callback . " is not allowed"
                )
            );
        }
    }
    
    foreach($requires as $require_ctx) {
        $resource_url = "";
        $resource_integrity = "";
        
        if (is_string($require_ctx)) {
            $resource_url = $require_ctx;
        } else if (is_array($require_ctx)) {
            $resource_url = array_get("url", $require_ctx, "");
            $resource_integrity = array_get("integrity", $require_ctx, "");
        }
        
        if (empty($resource_url))
            continue;
        
        try {
            $result = relay_fetch_url(array(
                "url" => $resource_url
            ));

            if ($result['success'] && $result['result']['status'] == 200) {
                $response = $result['result']['data'];
                if (!empty($resource_integrity)) {
                    if (verify_integrity($response, $resource_integrity)) {
                        load_script($response);
                    }
                } else {
                    load_script($response);
                }
            }
        } catch (Exception $e) {
            //echo $e->message;    // ignore an exception
        }
    }

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
        "url" => "https://farside.link/librex/api.php?" . http_build_query($search_params)
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
    $client_address = "";
    
    $client_address_candidates = array_filter(array_map("server_env_get", array(
        "HTTP_CLIENT_IP",
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_FORWARDED",
        "HTTP_X_CLUSTER_CLIENT_IP",
        "HTTP_FORWARDED_FOR",
        "HTTP_FORWARDED",
        "REMOTE_ADDR"
    )));
    if (count($client_address_candidates) > 0) {
        $client_address = $client_address_candidates[0];
    }
    
    return array(
        "data" => $client_address_candidates,
        "client_address" => $client_address    // compatible under version 0.1.5.18
    );
}

function get_user_agent() {
    $user_agents = array_filter(array_map("server_env_get", array(
        "HTTP_X_USER_AGENT",
        "HTTP_USER_AGENT"
    )));
    return implode(", ", $user_agents);
}

// check the user agent
$is_httpproxy = (strpos(get_user_agent(), "php-httpproxy/") === 0);
if (!$is_httpproxy) {
    $relay_allow_methods = explode(',', strtoupper(RELAY_ALLOW_METHODS));
    $relay_image_file_extensions = explode(',', strtolower(RELAY_IMAGE_FILE_EXTENSIONS));
    $relay_static_file_extensions = explode(',', strtolower(RELAY_STATIC_FILE_EXTENSIONS));

    if (in_array($_SERVER['REQUEST_METHOD'], $relay_allow_methods)) {
        $proxy_url = RELAY_PROXY_PASS . $_SERVER['REQUEST_URI'];

        // prevent an image file requests
        foreach ($relay_image_file_extensions as $file_extension) {
            if (strpos($proxy_url, $file_extension) !== false) {
                header("Location: https://http.cat/images/200.jpg");
                exit("");
            }
        }

        // prevent an static file requests
        foreach ($relay_static_file_extensions as $file_extension) {
            if (strpos($proxy_url, $file_extension) !== false) {
                exit("");
            }
        }

        $result = relay_fetch_url(array(
            "url" => $proxy_url
        ));
        if ($result['success']) {
            $response = str_replace(RELAY_PROXY_PASS, sprintf("%s://%s", $_SERVER['REQUEST_SCHEME'], $_SERVER['HTTP_HOST']), $result['result']['data']);
            if (RELAY_ENABLE_JS_REDIRECT) {
                if (strpos(strtolower(trim(substr($response, 0, 16))), "<!doctype html") === 0) {
                    $response .= "<script>setTimeout(function() { var a = document.createElement('a'); a.href = '" . $proxy_url . "'; document.body.appendChild(a); a.click(); }, 3000);</script>";
                }
            }
            exit($response);
        } else {
            http_response_code(500);
            exit($proxy_url . " is down.");
        }
    } else {
        exit('<!DOCTYPE html><html><head><title>It works!</title><meta charset="utf-8"></head><body><h1>It works!</h1><p><a href="https://github.com/gnh1201/caterpillar">Download the client</a></p><p>' . $_SERVER['HTTP_USER_AGENT'] . '</p><hr><p>' . DEFAULT_USER_AGENT . '</p></body></html>');
    }
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

        case "relay_get_env_hash":
            echo jsonrpc2_result_encode(relay_get_env_hash(), $context['id']);
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
