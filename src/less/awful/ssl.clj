(ns less.awful.ssl
  "Interacting with the Java crypto APIs is one of the worst things you can do
  as a developer. I'm so sorry about all of this."
  (:use [clojure.java.io :only [input-stream reader file]]
        [clojure.string :only [join]])
  (:require clojure.stacktrace)
  (:import (java.io FileInputStream
                    BufferedReader
                    InputStreamReader
                    PrintWriter)
           (java.security Key
                          KeyPair
                          KeyStore
                          KeyFactory
                          PublicKey
                          PrivateKey)
           (java.security.cert Certificate
                               CertificateFactory)
           (java.security.spec PKCS8EncodedKeySpec)
           (java.net InetSocketAddress)
           (javax.net.ssl SSLContext
                          SSLServerSocketFactory
                          SSLSocketFactory
                          KeyManager
                          KeyManagerFactory
                          TrustManager
                          TrustManagerFactory
                          X509KeyManager
                          X509TrustManager)
           (javax.xml.bind DatatypeConverter)))

(defn base64->binary
  "Parses a base64-encoded string to a byte array"
  [string]
  (DatatypeConverter/parseBase64Binary string))

(def x509-cert-factory
  "The X.509 certificate factory"
  (CertificateFactory/getInstance "X.509"))

(def rsa-key-factory
  "An RSA key factory"
  (KeyFactory/getInstance "RSA"))

(def key-store-password
  "You know, a mandatory password stored in memory so we can... encrypt... data
  stored in memory."
  (char-array "GheesBetDyPhuvwotNolofamLydMues9"))

(defn load-certificate
  "Loads an X.509 certificate from a file."
  [file]
  (with-open [stream (input-stream file)]
    (.generateCertificate x509-cert-factory stream)))

(defn public-key
  "Loads a public key from a .crt file."
  [file]
  (.getPublicKey (load-certificate file)))

(defn private-key
  "Loads a private key from a PKCS8 file."
  [file]
  (->> file
    slurp
    ; LOL Java
    (re-find #"(?ms)^-----BEGIN ?.*? PRIVATE KEY-----$(.+)^-----END ?.*? PRIVATE KEY-----$")
    last
    base64->binary
    PKCS8EncodedKeySpec.
    (.generatePrivate rsa-key-factory)))

(defn key-pair
  "Creates a KeyPair from a public and private key"
  [public-key private-key]
  (KeyPair. public-key private-key))

(defn key-store
  "Makes a keystore from a PKCS8 private key file, a public cert file, and the
  signing CA certificate."
  [key-file cert-file ca-cert-file]
  (let [key     (private-key key-file)
        cert    (load-certificate cert-file)
        ca-cert (load-certificate ca-cert-file)]
    (doto (KeyStore/getInstance (KeyStore/getDefaultType))
      (.load nil nil)
      ; alias, private key, password, certificate chain
      (.setKeyEntry "cert" key key-store-password
                    (into-array Certificate [cert])))))
;      (.setCertificateEntry "cacert" ca-cert))))

(defn trust-store
  "Makes a trust store, suitable for backing a TrustManager, out of a CA cert
  file."
  [ca-cert-file]
  (doto (KeyStore/getInstance "JKS")
    (.load nil nil)
    (.setCertificateEntry "cacert" (load-certificate ca-cert-file))))

(defn trust-manager
  "An X.509 trust manager for a KeyStore."
  [key-store]
  (let [factory (TrustManagerFactory/getInstance "PKIX" "SunJSSE")]
    ; I'm concerned that getInstance might return the *same* factory each time,
    ; so we'll defensively lock before mutating here:
    (locking factory
      (->> (doto factory (.init key-store))
        .getTrustManagers
        (filter (partial instance? X509TrustManager))
        first))))

(defn key-manager
  "An X.509 key manager for a KeyStore."
  [key-store]
  (let [factory (KeyManagerFactory/getInstance "SunX509" "SunJSSE")]
    (locking factory
      (->> (doto factory (.init key-store, key-store-password))
        .getKeyManagers
        (filter (partial instance? X509KeyManager))
        first))))

(defn ssl-context-generator
  "Returns a function that yields SSL contexts. Takes a PKCS8 key file, a
  certificate file, and a trusted CA certificate used to verify peers."
  [key-file cert-file ca-cert-file]
  (let [key-manager   (key-manager (key-store key-file cert-file ca-cert-file))
        trust-manager (trust-manager (trust-store ca-cert-file))]
    (fn build-context []
      (doto (SSLContext/getInstance "TLS")
        (.init (into-array KeyManager [key-manager])
               (into-array TrustManager [trust-manager])
               nil)))))

(defn ssl-context
  "Given a PKCS8 key file, a certificate file, and a trusted CA certificate
  used to verify peers, returns an SSLContext."
  [key-file cert-file ca-cert-file]
  ((ssl-context-generator key-file cert-file ca-cert-file)))

(def enabled-protocols
  "An array of protocols we support."
  (into-array String ["TLSv1"]))

(defn server-socket
  "Given an SSL context, makes a server SSLSocket."
  [context host port]
  (doto (.. context getServerSocketFactory createServerSocket)
    (.bind (InetSocketAddress. host port))
    (.setNeedClientAuth true)
    (.setEnabledProtocols enabled-protocols)))

(defn socket
  "Given an SSL context, makes a client SSLSocket."
  [context host port]
  (doto (-> context
          .getSocketFactory
          (.createSocket host port))
    (.setEnabledProtocols enabled-protocols)))

(defn test-ssl
  "Given keys and certificates for a client and server, and the signing CA for
  both, verify that we can use those files to make an SSL connection."
  [client-key-file client-cert-file
   server-key-file server-cert-file
   ca-cert-file]

  (let [port (+ 1024 (int (rand 60000)))
        started (promise)
        
        ; A dumb echo server
        server
        (future
          (try
            (with-open [server (server-socket (ssl-context server-key-file
                                                           server-cert-file
                                                           ca-cert-file)
                                 "localhost"
                                 port)]
              (prn :accepting)
              (deliver started :ready)
              (with-open [sock (.accept server)
                          in  (-> sock
                                .getInputStream
                                InputStreamReader.
                                BufferedReader.)
                          out (PrintWriter. (.getOutputStream sock))]
                (prn :accepted)
                (loop []
                  (when-let [s (.readLine in)]
                    (prn :server-got s)
                    (.println out s)
                    (.flush out)
                    (prn :server-sent s)
                    (recur)))
                (prn :server-done)))
            (catch Throwable t
              (clojure.stacktrace/print-stack-trace t))))]
   
    @started

    ; Connect to the local server, send some text, and verify it came back
    (prn :connecting)
    (with-open [sock (socket (ssl-context client-key-file
                                          client-cert-file
                                          ca-cert-file)
                       "localhost"
                       port)
                in (-> sock
                     .getInputStream
                     InputStreamReader.
                     BufferedReader.)
                out (PrintWriter. (.getOutputStream sock))]
      (prn :connected)
      (.println out "hi")
      (.flush out)
      (prn :client-sent)
      (let [response (.readLine in)]
        (prn :client-got response)
        (if (= "hi\n" response)
          :ok
          [:wrong response]))
      (prn :client-done))

    (prn :waiting-for-server)
    @server))
