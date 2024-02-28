# gnh1201/caterpillar
Caterpillar - The simple and parasitic web proxy with spam filter (formerly, php-httpproxy)

![title image](assets/img/title.jfif)

## How it works

### Basic structure
```
You <-> Proxy client (Python) <-> Parasitized proxy server (Optional, PHP) <-> On the Web
```
For example, build a simple web debugging proxy on the shared servers.

This project supports two modes of connection. The default is stateless. You can use the stateful mode to avoid being constrained by transfer capacity limits (e.g., `max_upload_size`).

### Spam filtering strategy
* [K-Anonymity](https://en.wikipedia.org/wiki/K-anonymity) test - Estimating whether the characters has been arranged by humans. (use [Have I Been Pwned](https://haveibeenpwned.com/Passwords))
* Not CAPTCHA - Image spam containing characters that look very similar to [CAPTCHA](https://en.wikipedia.org/wiki/CAPTCHA). (use [TrueCaptcha](https://truecaptcha.org/))
* VowelRatio10 - In characters arranged by humans, there is a high frequency of [vowels](https://en.wikipedia.org/wiki/Vowel) (aeiou) and [semivowels](https://en.wikipedia.org/wiki/Semivowel) (wy) and vowel-ending patterns included in strings that are 10 characters.
* Palindrome4 - Detect [palindromes](https://en.wikipedia.org/wiki/Palindrome) composed of 4 or more characters
* KnownWords4 - Detect [well-known words](https://github.com/dwyl/english-words) composed of 4 or more characters
* SearchEngine3 - In public search engine, the given string yields more than 2 results. (use [LibreY](https://github.com/Ahwxorg/librey))
* RepeatedNumber3 - Detect a repeated numbers 3 times or more.
* SSL decryption (MITM) when relaying to federated servers.

The strategies were implemented to respond to [the Fediverse Spam Attacks which started on the 15th of February](https://github.com/Mastodon-DE/blocklists/blob/main/spam%2F2024-02-15%2F2024-02-15-spam-mute-list.md).

## (Optional) Before to use
If you have an ***will be parasitize*** server that you want to proxy, you can install the `index.php` (assets/php/index.php) file. 

## How to use
1. Write a file `.env`(Linux) or `settings.ini`(Windows). Like this:

```
[settings]
PORT=5555
SERVER_URL=http://example.org
SERVER_CONNECTION_TYPE=stateless
CA_KEY=ca.key
CA_CERT=ca.crt
CERT_KEY=cert.key
CERT_DIR=certs/
OPENSSL_BINPATH=openssl
CLIENT_ENCODING=utf-8
LOCAL_DOMAIN=example.org
PROXY_PASS=http://127.0.0.1:3000
MASTODON_SERVER=
MASTODON_USER_TOKEN=
TRUECAPTCHA_USERID=
TRUECAPTCHA_APIKEY=
LIBREY_APIURL=
```

- (Optional) Install RootCA for SSL decryption ([Download CA Certificate](ca.crt))

```bash
sudo apt-get install -y ca-certificates
sudo cp ca.crt /usr/local/share/ca-certificates/caterpillar-ca.crt
sudo update-ca-certificates
```

2. Run `python3 server.py` and set HTTP(S) proxy in your web browser (e.g. Firefox)

3. Test [100MB](http://speed.hetzner.de/100MB.bin)/[SSL](https://speed.hetzner.de/100MB.bin), [1GB](http://speed.hetzner.de/1GB.bin)/[SSL](https://speed.hetzner.de/1GB.bin), [10GB](http://speed.hetzner.de/10GB.bin)/[SSL](http://speed.hetzner.de/10GB.bin) download and check the speed (e.g. https://speed.hetzner.de/1GB.bin)

3. Enjoy it

4. (Optional) With [Cloudflare](https://cloudflare.com), we can expect to accelerate the 4x speed and reduce the network stuck.

## (Optional) For Mastodon users

### In [Caterpillar installed directory]/settings.ini or .env
1. set `SERVER_URL` variable to `localhost` in `.env`  (e.g. `SERVER_URL=localhost`)
2. set `PROXY_PASS` variable to Mastodon backend URI (e.g. `http://127.0.0.1:3000`)
3. if you want use notification, set `MASTODON_SERVER`(server domain) and `MASTODON_USER_TOKEN`(access token) variables

### In [Mastodon installed directory]/env.production
1. set `http_proxy` variable to `http://localhost:5555` (e.g. `http_proxy=http://localhost:5555`)

### In NGINX configuration
1. Check your port number of Caterpillar (default: 5555)
1. In NGINX configuration (e.g. `/etc/nginx/conf.d/mastodon.conf`), edit the `proxy_pass` like a `proxy_pass http://localhost:5555`

## References
* https://github.com/anapeksha/python-proxy-server
* https://github.com/inaz2/proxy2

## Thanks to

### Pan Art by [@yeohangdang@i.peacht.art](https://i.peacht.art/@yeohangdang)
![Caterpillar Project Pan Art by @yeohangdang@i.peacht.art](assets/img/logo.png)

## Contact
* ActivityPub [@gnh1201@catswords.social](https://catswords.social/@gnh1201)
* abuse@catswords.net
