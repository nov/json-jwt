module JSON
  class JWK < Hash
    def initialize(public_key, options = {})
      replace encode(public_key, options)
    end

    private

    def encode(public_key, options = {})
      hash = case public_key
      when OpenSSL::PKey::RSA
        {
          alg: :RSA,
          exp: UrlSafeBase64.encode64(public_key.e.to_s(2)),
          mod: UrlSafeBase64.encode64(public_key.n.to_s(2))
        }
      else
        raise "Only RSA is supported now"
      end
      hash.merge(options)
    end
  end
end

require 'json/jwk/set'