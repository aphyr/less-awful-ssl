## Less Awful SSL

Working with Java's crypto libraries requires deep knowledge of a complex API,
language-specific key+certificate storage, and knowing how to avoid
long-standing bugs in the Java trust algorithms. This library tries to make it
less complicated to build simple SSL-enabled applications: given a CA
certificate and a signed key and cert, it can give you an SSLContext suitable
for creating TCPSockets directly, or handing off to Netty.

## Installation

https://clojars.org/less-awful-ssl

## Example

In this example we'll be using OpenSSL's stock CA configuration and the OpenSSL
perl script to create a CA's directory structure. I'm assuming you want your CA
signing key encrypted, but the client and server keys unencrypted (since
they'll be deployed to processes which run without human interaction).

```bash
# Create the CA directory hierarchy and keypair
# http://kremvax.net/howto/ssl-openssl-ca.html
cp /usr/lib/ssl/misc/CA.pl ca
./ca -newca

# Generate a server key
openssl genrsa -out server.key 4096

# Convert key to pcks8 because Java can't read OpenSSL's format
openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pkcs8

# Generate a cert request
openssl req -new -key server.key -out newreq.pem

# Sign request with CA
./ca -sign

# Rename signed cert and clean up unused files
mv newcert.pem server.crt
rm newreq.pem server.key

# And generate a client key+cert as well
openssl genrsa -out client.key 4096
openssl pkcs8 -topk8 -nocrypt -in client.key -out client.pkcs8
openssl req -new -key client.key -out newreq.pem
./ca -sign
mv newcert.pem client.crt
rm newreq.pem client.key
```

Now fire up a repl and test that your client and server keys can work together.
`(test-ssl)` takes a client key and cert, a server key and cert, and a trusted
CA certificate, and verifies that a client can talk to the server over a TLS
socket:

```clj
(use 'less.awful.ssl)
(def d (partial str "/path/to/keys/"))
(apply test-ssl (map d ["client.pkcs8" "client.crt" "server.pkcs8" "server.crt" "demoCA/cacert.pem"]))
```

```clj
:accepting
:connecting
:accepted
:connected
:client-sent
:server-got "hi"
:server-sent "hi"
:client-got "hi"
:client-done
:waiting-for-server
:server-done
```

Note that this *doesn't* work if you substitute some other certificate for the
trust chain, rather than the CA's:

```clj
(apply test-ssl (map d ["client.pkcs8" "client.crt" "server.pkcs8" "server.crt" "server.crt"]))
```

```clj
:accepting
:connecting
:connected:accepted

javax.net.ssl.SSLHandshakeException: null cert chain
...
SSLHandshakeException Received fatal alert: bad_certificate
  sun.security.ssl.Alerts.getSSLException (Alerts.java:192)
```

In your app, you'll want to distribute a particular PKCS secret key, the
corresponding signed certificate, and the CA certificate (to verify the
peer's identity). Then you can build an SSLContext:

```clj
(ssl-context "client.pkcs8" "client.crt" "ca.crt")
```

And given an SSL context, you can use it to construct a server or a client TCP
socket. See `core.clj/test-ssl` for an example:

```clj
(with-open [listener (-> (ssl-context "server.pkcs8" "server.crt" "ca.crt")
                         (server-socket "localhost" 1234))
      conn (.accept sock)]
  ...)
```

```clj
(with-open [sock (-> (ssl-context "client.pkcs8" "server.crt" "ca.crt")
                     (socket "localhost" 1234)]
  ...)
```

## Example with a PKCS12 client certificate and org.httpkit

Assume you've got a client key/certificate pair for `example.com` as a PKCS12 file `client.p12`, 
secured with _password_. Also, you've got the Certificate Autority that was used to 
sign the client certificate as `ca-cert.crt`.

Then you could do (your project needs http-kit, of course):

```clj
(use 'less.awful.ssl)
(require '[org.httpkit.client :as http])

(def password (char-array "secret"))

(def req (http/request {:sslengine (ssl-context->engine (ssl-p12-context "client.p12" password "ca-cert.crt"))
                        :url "https://example.com/needs-client-cert" :as :stream}))
```

## Thanks

I am indebted to Ben Linsay and Palomino Labs
(http://blog.palominolabs.com/2011/10/18/java-2-way-tlsssl-client-certificates-and-pkcs12-vs-jks-keystores/)
for their help in getting this all put together.

## License

Copyright © 2013 Kyle Kingsbury (aphyr@aphyr.com)

Distributed under the Eclipse Public License, the same as Clojure.
