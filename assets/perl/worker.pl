use JSON;
use IO::Socket::INET;
use Time::HiRes qw(time);

use constant DEFAULT_SOCKET_TIMEOUT => 1;
use constant STATEFUL_SOCKET_TIMEOUT => 30;

sub jsonrpc2_encode {
    my ($method, $params, $id) = @_;
    my $data = {
        jsonrpc => "2.0",
        method  => $method,
        params  => $params,
        id      => $id
    };
    return encode_json($data);
}

sub jsonrpc2_result_encode {
    my ($result, $id) = @_;
    my $data = {
        jsonrpc => "2.0",
        result  => $result,
        id      => $id
    };
    return encode_json($data);
}

sub jsonrpc2_error_encode {
    my ($error, $id) = @_;
    my $data = {
        jsonrpc => "2.0",
        error   => $error,
        id      => $id
    };
    return encode_json($data);
}

sub parse_headers {
    my ($str) = @_;
    my %headers;

    my @lines = split(/\r?\n/, $str);

    my $first_line = shift(@lines);
    $headers{'@method'} = [split(' ', $first_line)];

    foreach my $line (@lines) {
        if ($line =~ /^([^:]+):(.*)$/) {
            $headers{$1} = trim($2);
        }
    }

    return \%headers;
}

sub read_from_remote_server {
    my ($remote_address, $remote_port, $scheme, $data, $conn, $buffer_size, $id) = @_;
    if ($scheme ~~ ["https", "ssl", "tls"]) {
        $remote_address = "tls://" . $remote_address;
    }

    my $sock = IO::Socket::INET->new(
        PeerAddr => $remote_address,
        PeerPort => $remote_port,
        Proto    => 'tcp',
        Timeout  => DEFAULT_SOCKET_TIMEOUT
    );

    if (!$sock) {
        my $error = {
            status  => 502,
            code    => $!,
            message => $@
        };

        if (!$conn) {
            print jsonrpc2_error_encode($error, $id);
        } else {
            my $buf = sprintf("HTTP/1.1 502 Bad Gateway\r\n\r\n");
            $buf .= jsonrpc2_error_encode($error, $id);
            print $conn $buf;
        }
    } else {
        if (!$conn) {
            # send data
            print $sock $data;

            # receive data
            my $buf;
            while (!eof($sock) && defined($buf = <$sock>)) {
                print $buf;
            }
        } else {
            # send data
            my $buf;
            while (!eof($conn) && defined($buf = <$conn>)) {
                print $sock $buf;
            }

            # receive data
            $buf = "";
            while (!eof($sock) && defined($buf = <$sock>)) {
                print $conn $buf;
            }
        }

        close($sock);
    }
}

sub relay_request {
    my ($params, $id) = @_;
    my $buffer_size = $params->{'buffer_size'};
    my $request_data = decode_base64($params->{'request_data'});
    my $request_header = parse_headers($request_data);
    my $request_length = int($params->{'request_length'});
    my $client_address = $params->{'client_address'};
    my $client_port = int($params->{'client_port'});
    my $client_encoding = $params->{'client_encoding'};
    my $remote_address = $params->{'remote_address'};
    my $remote_port = int($params->{'remote_port'});
    my $scheme = $params->{'scheme'};
    my $datetime = $params->{'datetime'};

    if ($scheme ~~ ["https", "ssl", "tls"]) {
        $remote_address = "tls://" . $remote_address;
    }

    given ($request_header->{'@method'}[0]) {
        when ("CONNECT") {
            my $error = {
                status  => 405,
                code    => -1,
                message => "Method Not Allowed"
            };
            print jsonrpc2_error_encode($error, $id);
        }
        default {
            read_from_remote_server($remote_address, $remote_port, $scheme, $request_data, undef, $buffer_size, $id);
        }
    }
}

sub relay_connect {
    my ($params, $id) = @_;
    my $buffer_size = $params->{'buffer_size'};
    my $client_address = $params->{'client_address'};
    my $client_port = int($params->{'client_port'});
    my $client_encoding = $params->{'client_encoding'};
    my $remote_address = $params->{'remote_address'};
    my $remote_port = int($params->{'remote_port'});
    my $scheme = $params->{'scheme'};
    my $datetime = $params->{'datetime'};

    my $starttime = time();
    my $conn = IO::Socket::INET->new(
        PeerAddr => $client_address,
        PeerPort => $client_port,
        Proto    => 'tcp',
        Timeout  => STATEFUL_SOCKET_TIMEOUT
    );
    if (!$conn) {
        my $error = {
            status  => 502,
            code    => $!,
            message => $@
        };
        print jsonrpc2_error_encode($error, $id);
    } else {
        my $stoptime = time();
        my $connection_speed = int(($stoptime - $starttime) * 1000);
        my $data = jsonrpc2_encode("relay_accept", {
            success           => 1,
            connection_speed => $connection_speed
        }, $id);
        print $conn $data . "\r\n\r\n";

        read_from_remote_server($remote_address, $remote_port, $scheme, undef, $conn, $buffer_size, $id);
        close($conn);
    }
}

# Parse a context
my $json_input = do { local $/; <STDIN> };
my $context = decode_json($json_input);

# Check if it's JSON-RPC 2 (stateless)
if ($context->{'jsonrpc'} eq "2.0") {
    my $method = $context->{'method'};
    given ($method) {
        when ("relay_request") {
            relay_request($context->{'params'}, $context->{'id'});    # stateless mode
        }
        when ("relay_connect") {
            relay_connect($context->{'params'}, $context->{'id'});    # stateful mode
        }
    }
}
