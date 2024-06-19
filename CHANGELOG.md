## 1.6.0
  - Added new `ssl_enabled` setting for enabling/disabling the SSL configurations [#52](https://github.com/logstash-plugins/logstash-filter-http/pull/52)

## 1.5.1
  - Don't process response when the body is empty. [#50](https://github.com/logstash-plugins/logstash-filter-http/pull/50)

## 1.5.0
  - Added standardized SSL settings and deprecates their non-standard counterparts. Deprecated settings will continue to work, and will provide pipeline maintainers with guidance toward using their standardized counterparts [#49](https://github.com/logstash-plugins/logstash-filter-http/pull/49)
  - Added new `ssl_truststore_path`, `ssl_truststore_password`, and `ssl_truststore_type` settings for configuring SSL-trust using a PKCS-12 or JKS trust store, deprecating their `truststore`, `truststore_password`, and `truststore_type` counterparts.
  - Added new `ssl_certificate_authorities` setting for configuring SSL-trust using a PEM-formatted list certificate authorities, deprecating its `cacert` counterpart.
  - Added new `ssl_keystore_path`, `ssl_keystore_password`, and `ssl_keystore_type` settings for configuring SSL-identity using a PKCS-12 or JKS key store, deprecating their `keystore`, `keystore_password`, and `keystore_type` counterparts.
  - Added new `ssl_certificate` and `ssl_key` settings for configuring SSL-identity using a PEM-formatted certificate/key pair, deprecating their `client_cert` and `client_key` counterparts.
  - Added the `ssl_cipher_suites` option

## 1.4.3
  - DOC: add clarification on sending data as json [#48](https://github.com/logstash-plugins/logstash-filter-http/pull/48)

## 1.4.2
  - Fix: resolve content type when a content-type header contains an array [#46](https://github.com/logstash-plugins/logstash-filter-http/pull/46)

## 1.4.1
  - Fix: don't process response body for HEAD requests [#41](https://github.com/logstash-plugins/logstash-filter-http/pull/41)

## 1.4.0
  - Feat: added ssl_supported_protocols option [#38](https://github.com/logstash-plugins/logstash-filter-http/pull/38)
 
## 1.3.0
  - Feat: support ssl_verification_mode option [#37](https://github.com/logstash-plugins/logstash-filter-http/pull/37)

## 1.2.1
  - Fix: do not set content-type if provided by user [#36](https://github.com/logstash-plugins/logstash-filter-http/pull/36)

## 1.2.0
  - Feat: improve ECS compatibility [#35](https://github.com/logstash-plugins/logstash-filter-http/pull/35)

## 1.1.0
  - Add support for PUT requests [#34](https://github.com/logstash-plugins/logstash-filter-http/pull/34)

## 1.0.2
  - Fixed exception when using debug logging [#14](https://github.com/logstash-plugins/logstash-filter-http/pull/14)

## 1.0.1
  - Fixed minor documentation issues [#9](https://github.com/logstash-plugins/logstash-filter-http/pull/9)

## 1.0.0
  - Minor documentation fixes

## 0.1.0
  - Beta version of HTTP filter plugin based on @lucashenning's [REST filter](https://github.com/lucashenning/logstash-filter-rest).
