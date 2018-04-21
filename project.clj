(defproject less-awful-ssl "1.0.3"
  :description "Get an SSLContext without wanting to rip your hair out."
  :url "http://github.com/aphyr/less-awful-ssl"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [
    [javax.xml.bind/jaxb-api "2.3.0"]]
  :profiles {:dev {:dependencies [[org.clojure/clojure "1.9.0"]]}})
