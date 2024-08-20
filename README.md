# gnh1201/caterpillar

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.13346533.svg)](https://doi.org/10.5281/zenodo.13346533)

Caterpillar Proxy - The simple web debugging proxy (formerly, php-httpproxy)

![Cover image - Caterpillar on a tree looking at a rocket flying over the clouds](assets/img/cover.png)

## Use cases
* [Build a network tunnel using Python and the LAMP(PHP) stack.](https://qiita.com/gnh1201/items/40f9350ca6d308def6d4)
* [K-Anonymity for Spam Filtering: Case with Mastodon, and Misskey](https://qiita.com/gnh1201/items/09f4081f84610db3a9d3)
* [[YouTube Video] File Upload Vulnerability Attack Test (Caterpillar Proxy)](https://youtu.be/sPZOCgYtLRw)

## How it works

### Basic structure
```
You <-> Proxy client (Python) <-> Parasitized proxy server (Optional, PHP/LAMP) <-> On the Web
```

For example, build a simple web debugging proxy on the shared servers.

### Stateful mode
This project supports two modes of connection. The default is stateless. You can use the stateful mode to avoid being constrained by transfer capacity limits. See the [Stateful mode (github.com/gnh1201/caterpillar wiki)](https://github.com/gnh1201/caterpillar/wiki/Stateful-mode).

## (Optional) Before to use
If you have a server that ***will be parasitized*** and you want to proxy it, you should upload the `index.php` file to a shared server. The index.php file is located in the `assets/php` directory within this repository.

## How to use
1. Write a file `.env`(Linux) or `settings.ini`(Windows). Like this:

```
[settings]
PORT=5555
SERVER_URL=localhost
SERVER_CONNECTION_TYPE=
CA_KEY=ca.key
CA_CERT=ca.crt
CERT_KEY=cert.key
CERT_DIR=certs/
OPENSSL_BINPATH=openssl
CLIENT_ENCODING=utf-8
USE_EXTENSIONS=wayback.Wayback,bio.PyBio
```

***Note***: If using Caterpillar Proxy (Python) alone, set `SERVER_URL=localhost`. Otherwise, use the endpoint URL of the Worker script (PHP or Java), e.g., `SERVER_URL=http://example.org`.

- (Optional) Create a certificate for SSL decryption

```bash
chmod +x configure_certs.sh
./configure_certs.sh
sudo apt-get install -y ca-certificates
sudo cp ca.crt /usr/local/share/ca-certificates/caterpillar-ca.crt
sudo update-ca-certificates
```

2. Run `python3 server.py` and set HTTP(S) proxy in your web browser (e.g. Firefox, Chromium)

3. Test [100MB](http://speed.hetzner.de/100MB.bin)/[SSL](https://speed.hetzner.de/100MB.bin), [1GB](http://speed.hetzner.de/1GB.bin)/[SSL](https://speed.hetzner.de/1GB.bin), [10GB](http://speed.hetzner.de/10GB.bin)/[SSL](http://speed.hetzner.de/10GB.bin) download and check the speed.

3. Enjoy it

4. (Optional) With [Cloudflare](https://cloudflare.com), we can expect to accelerate the 4x speed and reduce the network stuck.

## Extensions
* [Web Console Available](https://pub-1a7a176eea68479cb5423e44273657ad.r2.dev/console.html)
* Fediverse (e.g., Mastodon): See the [Fediverse (github.com/gnh1201/caterpillar wiki)](https://github.com/gnh1201/caterpillar/wiki/Fediverse).
* Wayback (Private browsing with Google or Wayback cache): See the [Wayback (github.com/gnh1201/caterpillar wiki)](https://github.com/gnh1201/caterpillar/wiki/Wayback).

## Thanks to
* Pan Art by [@yeohangdang@i.peacht.art](#): [Image File](assets/img/logo.png)
* [GitHub Sponsors](https://github.com/sponsors/gnh1201)

## Contributors
<a href="https://github.com/gnh1201/caterpillar/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=gnh1201/caterpillar" alt="Contributors" />
</a>

## Our roadmap
![Roadmap image](assets/img/roadmap.png)

## Report abuse
* ActivityPub [@gnh1201@catswords.social](https://catswords.social/@gnh1201)
* abuse@catswords.net
* [Join Catswords on Microsoft Teams](https://teams.live.com/l/community/FEACHncAhq8ldnojAI)
