(ns less.awful.ssl-test
  (:require [clojure.test :refer :all]
            [less.awful.ssl :as ssl])
  (:import (java.nio.charset StandardCharsets)))

(deftest base64
  (let [test-str (apply str (repeat 4 "less-awful-ssl"))]
    (testing "decodes with line break"
      (is (= test-str
             (-> (ssl/base64->binary "bGVzcy1hd2Z1bC1zc2xsZXNzLWF3ZnVsLXNzbGxlc3MtYXdmdWwtc3NsbGVzcy1h\nd2Z1bC1zc2w=")
                 (String. StandardCharsets/UTF_8)))))
    (testing "decodes without line break"
      (is (= test-str
             (-> (ssl/base64->binary "bGVzcy1hd2Z1bC1zc2xsZXNzLWF3ZnVsLXNzbGxlc3MtYXdmdWwtc3NsbGVzcy1hd2Z1bC1zc2w=")
                 (String. StandardCharsets/UTF_8)))))))
