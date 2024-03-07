const express = require('express');
const bodyParser = require('body-parser');
const net = require('net');
const tls = require('tls');

const DEFAULT_SOCKET_TIMEOUT = 1000; // milliseconds
const STATEFUL_SOCKET_TIMEOUT = 30000; // milliseconds

const app = express();
const port = 3000;   // listening port number

app.use(bodyParser.json());

function jsonrpc2_encode(method, params, id = '') {
    const data = {
        jsonrpc: '2.0',
        method: method,
        params: params,
        id: id
    };
    return JSON.stringify(data);
}

function jsonrpc2_error_encode(error, id = '') {
    const data = {
        jsonrpc: '2.0',
        error: error,
        id: id
    };
    return JSON.stringify(data);
}

function read_from_remote_server(remote_address, remote_port, scheme, data = null, conn = null, buffer_size = 8192, id = '') {
    const sock = scheme === "https" || scheme === "ssl" || scheme === "tls"
        ? tls.connect(remote_port, remote_address)
        : net.connect(remote_port, remote_address);

    sock.on('error', error => {
        const err = {
            status: 502,
            code: error.code,
            message: error.message
        };

        if (!conn) {
            console.log(jsonrpc2_error_encode(err, id));
        } else {
            let buf = `HTTP/1.1 502 Bad Gateway\r\n\r\n`;
            buf += jsonrpc2_error_encode(err, id);
            conn.write(buf);
        }
    });

    sock.on('connect', () => {
        if (!conn) {
            sock.write(data);

            sock.on('data', buf => {
                console.log(buf.toString());
            });
        } else {
            conn.on('data', buf => {
                sock.write(buf);
            });

            sock.on('data', buf => {
                conn.write(buf);
            });
        }
    });

    sock.on('end', () => {
        sock.end();
    });
}

function relay_request(params, id = '') {
    const { buffer_size, request_data, request_length, client_address, client_port, client_encoding, remote_address, remote_port, scheme, datetime } = params;

    const request_header = parse_headers(Buffer.from(request_data, 'base64').toString());

    switch (request_header['@method'][0]) {
        case 'CONNECT':
            const err = {
                status: 405,
                code: -1,
                message: "Method Not Allowed"
            };
            console.log(jsonrpc2_error_encode(err, id));
            break;

        default:
            read_from_remote_server(remote_address, remote_port, scheme, Buffer.from(request_data, 'base64'), null, buffer_size, id);
    }
}

function relay_connect(params, id = '') {
    const { buffer_size, client_address, client_port, client_encoding, remote_address, remote_port, scheme, datetime } = params;

    const starttime = Date.now();
    const sock = net.connect(client_port, client_address);

    sock.on('error', error => {
        const err = {
            status: 502,
            code: error.code,
            message: error.message,
            _params: params
        };
        console.log(jsonrpc2_error_encode(err, id));
    });

    sock.on('connect', () => {
        const stoptime = Date.now();
        const connection_speed = Math.floor((stoptime - starttime));
        const data = jsonrpc2_encode("relay_accept", {
            success: true,
            connection_speed: connection_speed
        }, id);
        sock.write(data + '\r\n\r\n');

        read_from_remote_server(remote_address, remote_port, scheme, null, sock, buffer_size, id);
    });
}

function parse_headers(str) {
    const headers = {};

    const lines = str.split(/\r?\n/);

    const first_line = lines.shift();
    headers['@method'] = first_line.split(' ');

    lines.forEach(line => {
        const match = line.match(/^([^:]+):(.*)$/);
        if (match) {
            headers[match[1]] = match[2].trim();
        }
    });

    return headers;
}

function get_client_address(req, res) {
    const client_address = req.ip;
    const response = {
        client_address: client_address
    };
    res.json(response);
}

app.post('/', (req, res) => {
    const context = req.body;
    if (context.jsonrpc === '2.0') {
        const method = context.method;
        switch (method) {
            case 'relay_request':
                relay_request(context.params, context.id);
                break;

            case 'relay_connect':
                relay_connect(context.params, context.id);
                break;

            case 'get_client_address':
                get_client_address(req, res);
                break;

            default:
                res.status(400).send('Invalid method');
                break;
        }
    } else {
        res.status(400).send('Invalid JSON-RPC version');
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
