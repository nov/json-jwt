module JSON
  class JWS < JWT
    def initialize(jwt)
      header = jwt.header
      replace jwt
    end

    def sign!(private_key_or_secret, algorithm)
      header[:alg] = algorithm
      digest = OpenSSL::Digest::Digest.new "SHA#{algorithm.to_s[2, 3]}"
      self.signature = case algorithm
      when :HS256, :HS384, :HS512
        secret = private_key_or_secret
        OpenSSL::HMAC.digest(
          digest,
          secret,
          signature_base_string
        )
      when :RS256, :RS384, :RS512
        private_key = private_key_or_secret
        private_key.sign(
          digest,
          signature_base_string
        )
      end
      self
    end

    private

    def signature_base_string(header)
      [
        header,
        to_json
      ].collect do |segment|
        UrlSafeBase64.encode64 segment
      end.join('.')
    end
  end
end