# JSON::JWT

JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby

[![Build Status](https://secure.travis-ci.org/nov/json-jwt.png)](http://travis-ci.org/nov/json-jwt)

## Installation

  gem install json-jwt

## Resources

* View Source on GitHub (https://github.com/nov/json-jwt)
* Report Issues on GitHub (https://github.com/nov/json-jwt/issues)

## Examples

### Encoding

```ruby
require 'json/jwt'

claim = {
  iss: 'nov',
  exp: 1.week.from_now,
  nbf: Time.now
}

# No signature, no encryption
jwt = JSON::JWT.new(claim).to_s

# With signiture, no encryption
jws = JSON::JWT.new(claim).sign(key, algorithm) # algorithm is optional. default HS256
jws.to_s # => header.payload.signature
jws.to_json(syntax: :general) # => General JWS JSON Serialization
jws.to_json(syntax: :flatten) # => Flattened JWS JSON Serialization

# With signature & encryption
jwe = jws.encrypt(key, algorithm, encryption_method) # algorithm & encryption_method are optional. default RSA1_5 & A128CBC-HS256
jwe.to_s # => header.encrypted_key.iv.cipher_text.authentication_tag
```

For details about `key` and `algorithm`, see
[JWS Spec](https://github.com/nov/json-jwt/blob/master/spec/json/jws_spec.rb) and
[Sign Key Fixture Generator](https://github.com/nov/json-jwt/blob/master/spec/helpers/sign_key_fixture_helper.rb).

### Decoding

```ruby
jwt_string = "jwt_header.jwt_claims.jwt_signature"

JSON::JWT.decode(jwt_string, key)
```

## Note on Patches/Pull Requests

* Fork the project.
* Make your feature addition or bug fix.
* Add tests for it. This is important so I don't break it in a
  future version unintentionally.
* Commit, do not mess with rakefile, version, or history.
  (if you want to have your own version, that is fine but bump version in a commit by itself I can ignore when I pull)
* Send me a pull request. Bonus points for topic branches.

## Copyright

Copyright (c) 2011 nov matake. See LICENSE for details.
