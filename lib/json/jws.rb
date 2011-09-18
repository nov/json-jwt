module JSON
  class JWS < JWT
    class InvalidFormat < JWT::InvalidFormat; end
    class VerificationFailed < JWT::VerificationFailed; end

    def initialize(jwt)
      replace jwt
      raise InvalidFormat.new('Signature Algorithm Required') unless algorithm
    end

    def sign!(private_key_or_secret)
      self.signature = sign signature_base_string, private_key_or_secret
      self
    end

    def verify(signature_base_string, signature, private_key_or_secret)
      sign(signature_base_string, private_key_or_secret) == signature or
      raise VerificationFailed
    end

    private

    def algorithm
      @header[:alg]
    end

    def signature_base_string
      [
        header.to_json,
        self.to_json
      ].collect do |segment|
        UrlSafeBase64.encode64 segment
      end.join('.')
    end

    def sign(signature_base_string, private_key_or_secret)
      digest = OpenSSL::Digest::Digest.new "SHA#{algorithm.to_s[2, 3]}"
      case algorithm
      when :HS256, :HS384, :HS512
        secret = private_key_or_secret
        OpenSSL::HMAC.digest digest, secret, signature_base_string
      when :RS256, :RS384, :RS512
        private_key = private_key_or_secret
        private_key.sign digest, signature_base_string
      when :ES256, :ES384, :ES512
        # TODO
        raise NotImplementedError.new
      else
        raise InvalidFormat.new('Unknown Signature Algorithm')
      end
    end
  end
end