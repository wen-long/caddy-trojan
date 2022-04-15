# Caddy-Trojan

## Build with xcaddy
```
$ xcaddy build --with github.com/wen-long/caddy-trojan
```

##  Config (JSON)
```jsonc
{
  "apps": {
    "http": {
      "http_port": 1999,
      "servers": {
        "srv0": {
          "listen": [
            ":443"
          ],
          "listener_wrappers": [
            {
              "users": [
                "username1",
                "username2"
              ],
              "wrapper": "trojan"
            }
          ],
          "routes": [
            {
              "handle": [
                {
                  "handler": "subroute",
                  "routes": [
                    {
                      "handle": [
                        {
                          "handler": "reverse_proxy",
                          "upstreams": [
                            {
                              "dial": "127.0.0.1:80"
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ],
          "tls_connection_policies": [
            {
              "alpn": [
                "http/1.1"
              ]
            }
          ]
        }
      }
    },
    "tls": {
      "certificates": {
        "automate": [
          "your.domain.com"
        ]
      }
    }
  }
}
```
##  Config (Caddyfile)

```
{
   http_port 1999
   servers {
      listener_wrappers {
         trojan {
             user username1
             user username2
         }
      }
   }
}

:443, your.domain.com {
   tls {
      alpn http/1.1
   }
   route {
      reverse_proxy 127.0.0.1:80
   }
}
```

