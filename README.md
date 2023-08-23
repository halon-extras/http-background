# HTTP background request plugin

Send HTTP requests from HSL asynchronously as it suspends the current exeuction thread until done.

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-http-background
```

### RHEL

```
yum install halon-extras-http-background
```

## Configuration

For the configuration schema, see [http-background.schema.json](http-background.schema.json). Below is a sample configuration.

### smtpd.yaml

```
plugins:
  - id: http-background
    config:
      threads:
        - id: default
          max_total: 100
          max_host: 20
```

## Exported functions

These functions needs to be [imported](https://docs.halon.io/hsl/structures.html#import) from the `extras://http-background` module path.

### http_background(id, url [, options [, post]])

**Params**

- id `string` (**required**)
- url `string` (**required**)
- options `array` 
    - tls_verify_peer `boolean` (default `true`)
    - tls_verify_host `boolean` (default `true`)
    - tls_verify_cert `array`
        - x509 `X509Resource`
        - privatekey `PrivateKeyResource`
    - timeout `number` (default no timeout)
    - connect_timeout `number` (default `300`)
    - max_file_size `number` maxmium file size to retrieve (default no limit)
    - method `string` the request method (default depending on payload)
    - proxy `string` custom proxy server
    - encoder `string` encoder of the POST data (supported: base64)
    - headers (`array` of `string`) additional headers, default empty array
    - sourceip `string` the sourceip (ipv4 or ipv6)
- post `File`, `array` or `string`

Type default POST Content-Type header is based on the POST data type

  - `File`: `application/octet-stream`
  - `array`: `multipart/form-data`
  - `string`: `application/x-www-form-urlencoded`

If post is an `array` the format should be associative `array` where the key (`string`) is the field name

  - data `File` or `string` content of the field
  - type `string` content-type of the field
  - filename `string` filename of the field
  - encoder `string` encoder of the field (see curl_mime_encoder)

**Returns**

An associative array with a `status` and `content` key (if the HTTP request was submitted with a response code) or a `error` key (if an error occurred).

**Example**

```
import { http_background } from "extras://http-background";

echo http_background(
    "default",
    "https://httpbin.org/get?a=b"
);

echo http_background(
    "default",
    "https://httpbin.org/post?a=b",
    [],
    ["field1" => ["data" => "test"]]
);
```
