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

For JWS
* `HS256`
* `HS384`
* `HS512`
* `RS256`
* `RS384`
* `RS512`
* `ES256`
* `ES384`
* `ES512`

For JWE
* `RSA1_5`
* `RSA-OAEP`
* `dir`

Supported `encryption_method` are
* `A128GCM`
* `A256GCM`
* `A128CBC-HS256`
* `A256CBC-HS512`

#### Decoding

```ruby
jwt_string = "jwt_header.jwt_claims.jwt_signature"

JSON::JWT.decode(jwt_string, key)
```

Supported `key` are
* `String`
* `OpenSSL::PKey::RSA`
* `OpenSSL::PKey::EC`
* `JSON::JWK`
* `JSON::JWK::Set` # NOTE: proper `JSON::JWK` in the set will be selected by `kid` in the header.
* `:skip_verification` # NOTE: skip signature verification

### JWK

`JSON::JWK.new` accepts these instances as key inputs
* `String` # NOTE: for shared key (kty=oct)
* `OpenSSL::PKey::RSA`
* `OpenSSL::PKey::EC`
* `JSON::JWK`
* `Hash`

#### RSA

```ruby
k = OpenSSL::PKey::RSA.new(2048)

k.to_jwk
# => JSON::JWK (private key)

k.public_key.to_jwk
# => JSON::JWK (public key)
```

```ruby
jwk = JSON::JWK.new(
  kty: "RSA",
  e: "AQAB",
  n: "0OIOijENzP0AXnxP-X8Dnazt3m4NTamfNsSCkH4xzgZAJj2Eur9-zmq9IukwN37lIrm3oAE6lL4ytNkv-DQpAivKLE8bh4c9qlB9o32VWyg-mg-2af-JlfGXYoaCW2GDMOV6EKqHBxE0x1EI0tG4gcNwO6A_kYtK6_ACgTQudWz_gnPrL-QCunjIMbbrK9JqgMZhgMARMQpB-j8oet2FFsEcquR5MWtBeAn7qC1AD2ya0EmzplZJP6oCka_VVuxAnyWfRGA0bzCBRIVbcGUXVNIXpRtA_4960e7AlGfMSA-ofN-vo7v0CMkA8BwpZHai9CAJ-cTCX1AVbov83LVIWw",
  d: "BZCgNopMBdQPuHSzZMA_hmnfBHgGHrWQKlNd7x-NkCGWf-5PpPIJHNK3K0DvKetVi3FLNRYTS3ctvqeyoXgyR36HKlsJLrkpqWnvjvV_jygpUs1sXLKUJcyD7foLawfUCO90KxF_-24367967rLrqXldehkw2F3Ppy2Dw5FyU2qBqcpLeruBt6-UdMmBufzNQLisPJ67vhCTVrTNaHDDeCK2gHI3gqsnnbzOMS45VknmFOgKUp1C8GZu5BsT-AdDApEtY-DRZqnr6BxZv4-hG5OdEUA4_LCaI6JwlaAzv0Z74jpBZDC73cXWKJPgVuhARZcll5cexB2_EpgZDB6akQ",
  p: "6GFVNgaXcW39NG-sRqKPzFtz1usfAkdCydPmfZirfHRhSh3OojX3Glbe7BI_SRSOLc2d2xw2_ZwKRlruY44aGEf4s5gD_nKgq2QS-1cA5uNAU91wRtY2rdoAuCnk2BX3WTZPnzyxkokFY0S0R_9IpJhRz72ggxYyhx0ymRUBIWc",
  q: "5h1QX2JWLbcIT_cfrkmMoES1z06Fu88MLORYppiRDqkXl3CJFxKFtKJtDPLTf0MeTFexh81V52Ztsd8UttPInyDl9l5T0AOy8NmqHKqjI1063uy4bnHWetN7ovHftc_TOlnldAoQh9bmhZAhEyGlwa5Kros2YD2amIgDhcOmRO0"
)
jwk.to_key
# => OpenSSL::PKey::RSA (private key)

jwk = JSON::JWK.new(
  kty: "RSA",
  e: "AQAB",
  n: "0OIOijENzP0AXnxP-X8Dnazt3m4NTamfNsSCkH4xzgZAJj2Eur9-zmq9IukwN37lIrm3oAE6lL4ytNkv-DQpAivKLE8bh4c9qlB9o32VWyg-mg-2af-JlfGXYoaCW2GDMOV6EKqHBxE0x1EI0tG4gcNwO6A_kYtK6_ACgTQudWz_gnPrL-QCunjIMbbrK9JqgMZhgMARMQpB-j8oet2FFsEcquR5MWtBeAn7qC1AD2ya0EmzplZJP6oCka_VVuxAnyWfRGA0bzCBRIVbcGUXVNIXpRtA_4960e7AlGfMSA-ofN-vo7v0CMkA8BwpZHai9CAJ-cTCX1AVbov83LVIWw"
)
jwk.to_key
# => OpenSSL::PKey::RSA (public key)
```

#### EC

```ruby
k = OpenSSL::PKey::EC.new('prime256v1').generate_key

k.to_jwk
# => JSON::JWK (private key)

k.private_key = nil
k.to_jwk
# => JSON::JWK (public key)
```

```ruby
jwk = JSON::JWK.new(
  kty: "EC",
  crv: "P-256",
  x: "D4L5V9QocZvfuEEGfGD5YCEbIcXR-KfF7RqqZUaovJ8",
  y: "VX0T94KUo0YkhuvT2q0MXMOTtfaIjDS4fb9ii54g4gU",
  d: "MCOTV6Ncg7KTuGh1hTa029ZVkqdlaXaYnfLSkZjJ_uE"
)
jwk.to_key
# => OpenSSL::PKey::EC (private key)

jwk = JSON::JWK.new(
  kty: "EC",
  crv: "P-256",
  x: "D4L5V9QocZvfuEEGfGD5YCEbIcXR-KfF7RqqZUaovJ8",
  y: "VX0T94KUo0YkhuvT2q0MXMOTtfaIjDS4fb9ii54g4gU"
)
jwk.to_key
# => OpenSSL::PKey::EC (public key)
```

#### oct

```ruby
k = JSON::JWK.new 'secret'
k.to_jwk
# => JSON::JWK
```

```ruby
jwk = JSON::JWK.new(
  kty: "oct",
  k: "secret"
)
jwk.to_key
# => String
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
