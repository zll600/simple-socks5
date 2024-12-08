# Simple Socks5

## Usage

start relay B
````shell
$ go run ./tunnel_kcp/main.go -role B -secret xxx \
  -listenAddr 127.0.0.1:2001 -remoteAddr job.toutiao.com:80
````

start relay A
````shell
$ go run ./tunnel_kcp/main.go -role A -secret xxx
````

send http request
````shell
$ nc 127.0.0.1 2000 -v                  
GET /s/JxLbWby HTTP/1.1 
Host: job.toutiao.com `
````


## Acknowledgement

- <https://mp.weixin.qq.com/s/Gr7b5Guj4wL15YmIZmvKeQ>
- <https://www.v2ex.com/t/743203>

## Reference

- <https://en.wikipedia.org/wiki/SOCKS>
- https://datatracker.ietf.org/doc/html/rfc1928

