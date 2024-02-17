# php-httpproxy
HTTP(S) proxy implementation with PHP socket

## How to works
```
You <-----> HTTP(S) proxy (Python) <-----> Web hosting (PHP) <-----> On the Web
```

HTTP(S) proxy over the web hosting!

## How to use

1. Write a file with filename like `.env`(Linux) or `settings.ini`(Windows). Like this:

```
[settings]
PORT=5555
SERVER_URL=http://example.org
CA_KEY=ca.key
CA_CERT=ca.crt
CERT_KEY=cert.key
CERT_DIR=certs/
OPENSSL_BINPATH=openssl
CLIENT_ENCODING=utf-8
```

1.1. (Optional) Install ca.cert
```bash
$ sudo apt-get install -y ca-certificates
$ sudo cp ca.crt /usr/local/share/ca-certificates/php-httpproxy-ca.crt
$ sudo update-ca-certificates
```

2. Run `python server.py` and set HTTP(S) proxy in your web browser (e.g. Firefox)

3. Test [100MB](http://speed.hetzner.de/100MB.bin)/[SSL](https://speed.hetzner.de/100MB.bin), [1GB](http://speed.hetzner.de/1GB.bin)/[SSL](https://speed.hetzner.de/1GB.bin), [10GB](http://speed.hetzner.de/10GB.bin)/[SSL](http://speed.hetzner.de/10GB.bin) download and check the speed (e.g. https://speed.hetzner.de/1GB.bin)

3. Enjoy it

4. (Optional) With [Cloudflare](https://cloudflare.com), we can expect to accelerate the 4x speed and reduce the network stuck.

## References
* https://github.com/anapeksha/python-proxy-server
* https://github.com/inaz2/proxy2

## Contact
* abuse@catswords.net
