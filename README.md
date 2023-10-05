# acme-client-rs

ACME Client in Rust

Acme client help:
```shell
$ acme-client --help
acme-client 1.1.0
Hatter Jiang <jht5945@gmail.com>
Acme auto challenge client, acme-client can issue certificates from Let's encrypt

USAGE:
    acme-client [FLAGS] [OPTIONS]

FLAGS:
        --allow-interact             Allow interact
        --check                      Check cert config
    -h, --help                       Prints help information
        --hide-logo                  Hide logo
    -K, --skip-verify-certificate    Skip verify certificate
    -k, --skip-verify-ip             Skip verify public ip
    -v, --verbose                    Verbose
    -V, --version                    Print version

OPTIONS:
    -a, --algo <algo>            Pki algo [default: ec384]
        --cert-dir <cert-dir>    Certificate dir
    -c, --config <config>        Cert config
        --dir <dir>              Account key dir [default: acme_dir]
    -d, --domain <domain>...     Domains
        --email <email>          Contract email
    -m, --mode <mode>            Mode [default: prod]
    -o, --outputs <outputs>      Outputs file
    -p, --port <port>            Http port [default: 80]
        --timeout <timeout>      Timeout (ms) [default: 5000]
    -t, --type <type>            Type http or dns [default: http]
```

签发一张证书示例
* 先将域名指向对应的服务器，保证服务器上的 `80` 端口可被互联网访问
* `acme-client --email your-email@example.com --domain your-domain.example.com`

使用参数 `--config` 时的配置文件示例:
```json
{
  "port": 18342,
  "credentialSuppliers": {
    "alibabacloud": "account://access_key_id:access_key_secret@alibabacloud?id=dns"
  },
  "triggerAfterUpdate": ["/usr/local/nginx/nginx", "-s", "reload"],
  "notifyToken": "dingtalk:access_token?sec_token",
  "certItems": [{
    "path": "dir_cryptofan_org",
    "dnsNames": ["cryptofan.org", "www.cryptofan.org"]
  }, {
    "path": "dir_webauthn_host",
    "dnsNames": ["webauthn.host", "*.webauthn.host"],
    "type": "dns",
    "supplier": "alibabacloud"
  }]
}
```

Nginx.conf 配置：
```nginx.conf
location /.well-known/acme-challenge/ {
    proxy_http_version 1.1;
    proxy_pass http://127.0.0.1:18342/.well-known/acme-challenge/;
}
```

通过命令行交互创建DNS挑战证书：
```shell
acme-client --port 0 -t dns --allow-interact --email email@example.com -d example.net
```

* `email@example.com` -- your email
* `example.net` -- your domain

出现以下提示时需要自行配置DNS，配置完成后按"回车"：
```shell
[INFO ] You need to config dns manually, press enter to continue...
```


<br>

Cross build uses: 
- ~~https://github.com/messense/rust-musl-cross~~
- https://github.com/emk/rust-musl-builder

