import socket
import argparse
import json
import hashlib
import sys

from decouple import config

try:
    client_encoding = config('CLIENT_ENCODING', default='utf-8')
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

parser = argparse.ArgumentParser()
parser.add_argument('--buffer_size', help="Number of samples to be used", default=8192, type=int)

args = parser.parse_args()
buffer_size = args.buffer_size

def jsonrpc2_create_id(data):
    return hashlib.sha1(json.dumps(data).encode(client_encoding)).hexdigest()

def jsonrpc2_encode(method, params = None):
    data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    id = jsonrpc2_create_id(data)
    data['id'] = id
    return (id, json.dumps(data))

def main(args):
    # make the message
    id, message = jsonrpc2_encode('container_init', {
        "success": True
    })
    print (message)

    # connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 5555))

    # send a message
    sock.send(message.encode(client_encoding))
    response = sock.recv(buffer_size)
    jsondata = json.loads(response.decode(client_encoding))
    print (jsondata)

if __name__== "__main__":
    main(sys.argv)
