module JSON
  class JWK
    class << self
      def encode(public_key, kid = nil)
        json = case public_key
        when OpenSSL::PKey::RSA
          {
            alg: :RSA,
            exp: UrlSafeBase64.encode64(public_key.e.to_s(2)),
            mod: UrlSafeBase64.encode64(public_key.n.to_s(2))
          }
        else
          raise "Only OpenSSL::PKey::RSA is supported now"
        end
        json[:kid] = kid if kid.present?
        json
      end
    end
  end
end