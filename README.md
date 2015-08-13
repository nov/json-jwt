# JSON::JWT

JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby

[![Build Status](https://secure.travis-ci.org/nov/json-jwt.png)](http://travis-ci.org/nov/json-jwt)

## Installation

  gem install json-jwt

## Resources

* View Source on GitHub (https://github.com/nov/json-jwt)
* Report Issues on GitHub (https://github.com/nov/json-jwt/issues)

## Examples

### JWT, JWS and JWE

#### Encoding

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

Supported `key` are
* `String`
* `OpenSSL::PKey::RSA`
* `OpenSSL::PKey::EC`
* `JSON::JWK`
* `JSON::JWK::Set` # NOTE: proper `JSON::JWK` in the set will be selected by `kid` in the header.

Supported `algorithm` are

* For JWS
** `HS256`
** `HS384`
** `HS512`
** `RS256`
** `RS384`
** `RS512`
** `ES256`
** `ES384`
** `ES512`
* For JWE
** `RSA1_5`
** `RSA-OAEP`
** `dir`

Supported `encryption_method` are
* `A128GCM`
* `A256GCM`
* `A128CBC-HS256`
* `A256CBC-HS512`

For details about `key` and `algorithm`, see
[JWS Spec](https://github.com/nov/json-jwt/blob/master/spec/json/jws_spec.rb) and
[Sign Key Fixture Generator](https://github.com/nov/json-jwt/blob/master/spec/helpers/sign_key_fixture_helper.rb).

#### Decoding

```ruby
jwt_string = "jwt_header.jwt_claims.jwt_signature"

JSON::JWT.decode(jwt_string, key)
```

### JWK

#### RSA

```ruby
k = OpenSSL::PKey::RSA.new(2048)
p k.to_jwk
# => JSON::JWK

jwk = JSON::JWK.new(
  kty: "RSA",
  e: "AQAB",
  n: "utwietJHu65N7kIa52bMkKgbS1CGmhKNDx3gTBEvQmQhg1BbKHfdmqapMt699T-aloeslYxeO9ItOhprnE0vG-pbDUE7Jg51gtK6kjpLFZOLNpRHJnRikyF6dav1IdJa4fSpOiEJiHk_DuFnAMI04_1H_NISn1TzEBflbyb6BSyIPkfO9433zR2-clvHdIXppq-N272vHA64Xp5hslzY91QodXo5--9iIblPVxzd9aH-aBMSkRbmlIKuz14tWhR-6RLNsWtqxWfKvgeoBLh5e9E5MrlNuRnaaLqHOMWrW1l9985eqmCD3PD4wjwINFKrU4L0fMBCHgCDAZLhbLfUJw",
  d: "NtFBpDpwJNT7s7vc3KnBtWY7q5qSAj0S-K5REL-x1448bqNyOqr_bdEarfu-SmZAWYyvyqeFNZNxBSyfCRlzioLz9y19xqpTOu_LH_7N7CR-oKJbRSK7kGIv5Llvjl6BnuwBgTYT799x6lGhwA05KvEw3zBZmjh3ne8Etdj_W-i2LDBDUimgmVrgXWY1KvWFgh2zpptIINX2Q8UxV121bdcBIbj008Cs64m2mMpaa3ggqqNoXnYb8HnJDnYx-WIbUMHJ2-hpZAsVFNet8ZVEMt4cTKaTHY23m9Ditj-7VfFzkoiH9Yj45ewJMpcssadnAPrBgKbjTFuTdJfP8IqMoQ"
)
jwk.to_key
# => OpenSSL::PKey::RSA
```

#### EC

```ruby
k = OpenSSL::PKey::RSA.new(2048).generate_key
k.to_jwk
# => JSON::JWK

jwk = JSON::JWK.new(
  kty: "EC",
  crv: "P-256",
  x: "D4L5V9QocZvfuEEGfGD5YCEbIcXR-KfF7RqqZUaovJ8",
  y: "VX0T94KUo0YkhuvT2q0MXMOTtfaIjDS4fb9ii54g4gU",
  d: "MCOTV6Ncg7KTuGh1hTa029ZVkqdlaXaYnfLSkZjJ_uE"
)
jwk.to_key
# => OpenSSL::PKey::EC
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
