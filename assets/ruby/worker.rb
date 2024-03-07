require 'socket'
require 'json'

DEFAULT_SOCKET_TIMEOUT = 1
STATEFUL_SOCKET_TIMEOUT = 30

def jsonrpc2_encode(method, params, id = '')
  {
    "jsonrpc" => "2.0",
    "method" => method,
    "params" => params,
    "id" => id
  }.to_json
end

def jsonrpc2_result_encode(result, id = '')
  {
    "jsonrpc" => "2.0",
    "result" => result,
    "id" => id
  }.to_json
end

def jsonrpc2_error_encode(error, id = '')
  {
    "jsonrpc" => "2.0",
    "error" => error,
    "id" => id
  }.to_json
end

def parse_headers(str)
  headers = {}
  lines = str.split(/\r?\n/)
  first_line = lines.shift.split(' ')
  headers['@method'] = first_line
  lines.each do |line|
    if match = line.match(/^([^:]+):(.*)$/)
      headers[match[1]] = match[2].strip
    end
  end
  headers
end

def read_from_remote_server(remote_address, remote_port, scheme, data = nil, conn = nil, buffer_size = 8192, id = '')
  if ["https", "ssl", "tls"].include?(scheme)
    remote_address = "tls://" + remote_address
  end

  sock = TCPSocket.open(remote_address, remote_port)
  if sock.nil?
    error = {
      "status" => 502,
      "code" => error_code,
      "message" => error_message
    }

    if conn.nil?
      puts jsonrpc2_error_encode(error, id)
    else
      buf = "HTTP/1.1 502 Bad Gateway\r\n\r\n"
      buf += jsonrpc2_error_encode(error, id)
      conn.write(buf)
    end
  else
    if conn.nil?
      sock.write(data) unless data.nil?

      buf = nil
      while buf != false && !sock.eof?
        buf = sock.gets(buffer_size)
        puts buf
      end
    else
      buf = nil
      while buf != false && !conn.eof?
        buf = conn.gets(buffer_size)
        sock.write(buf)
      end

      buf = nil
      while buf != false && !sock.eof?
        buf = sock.gets(buffer_size)
        conn.write(buf)
      end
    end

    sock.close
  end
end

def relay_request(params, id = '')
  buffer_size = params['buffer_size']
  request_data = Base64.decode64(params['request_data'])
  request_header = parse_headers(request_data)
  request_length = params['request_length'].to_i
  client_address = params['client_address']
  client_port = params['client_port'].to_i
  client_encoding = params['client_encoding']
  remote_address = params['remote_address']
  remote_port = params['remote_port'].to_i
  scheme = params['scheme']
  datetime = params['datetime'] # format: %Y-%m-%d %H:%M:%S.%f

  if ["https", "ssl", "tls"].include?(scheme)
    remote_address = "tls://" + remote_address
  end

  case request_header['@method'][0]
  when "CONNECT"
    error = {
      "status" => 405,
      "code" => -1,
      "message" => "Method Not Allowed"
    }
    puts jsonrpc2_error_encode(error, id)
  else
    read_from_remote_server(remote_address, remote_port, scheme, request_data, nil, buffer_size, id)
  end
end

def relay_connect(params, id = '')
  buffer_size = params['buffer_size']
  client_address = params['client_address']
  client_port = params['client_port'].to_i
  client_encoding = params['client_encoding']
  remote_address = params['remote_address']
  remote_port = params['remote_port'].to_i
  scheme = params['scheme']
  datetime = params['datetime'] # format: %Y-%m-%d %H:%M:%S.%f

  starttime = Time.now.to_f
  conn = TCPSocket.open(client_address, client_port)
  if conn.nil?
    error = {
      "status" => 502,
      "code" => error_code,
      "message" => error_message,
      "_params" => params
    }
    puts jsonrpc2_error_encode(error, id)
  else
    stoptime = Time.now.to_f
    connection_speed = ((stoptime - starttime) * 1000).to_i
    data = jsonrpc2_encode("relay_accept", {
      "success" => true,
      "connection_speed" => connection_speed
    }, id)
    conn.write(data + "\r\n\r\n")

    read_from_remote_server(remote_address, remote_port, scheme, nil, conn, buffer_size, id)
    conn.close
  end
end

context = JSON.parse(STDIN.read)

if context['jsonrpc'] == "2.0"
  method = context['method']
  case method
  when "relay_request"
    relay_request(context['params'], context['id'])
  when "relay_connect"
    relay_connect(context['params'], context['id'])
  end
end
