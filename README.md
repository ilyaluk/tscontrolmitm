# tscontrolmitm

This is a simple server that implements tailscale control plane protocol that allows to proxy and log all control plane traffic.

Note that this hijacks control protocol and transparently replaces client machine keys, because encrpytion is performed using control plane key and machine key. Having private machine key allows to impersonate the machine for all purposes, including access to the network. The replacement private keys are stored in plaintext in state file.

Suppose you want to trace control traffic for HeadScale or other control server. Start like this:

```
go run . -upstream-url https://your.server.com
```

This will store state in `./state.json` and listen on `*:8080`. Next, connect your tailscale with:

```
tailscale up --login-url http://localhost:8080 #...
```

(or alternative for GUI clients, all of them support custom login URL). Now you can see all control plane traffic in the console. See `go run . -h` to disable some logs.

### Future work
* Support legacy endpoints `/machine/*`
* Support TLS listening (required for DERP)
* MitM DERP traffic
* MitM node keys and override endpoints to intercept network traffic
