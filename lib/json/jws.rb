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

    def verify(signature_base_string, signature, public_key_or_secret)
      valid?(signature_base_string, signature, public_key_or_secret) or
      raise VerificationFailed
    end

    private

    def algorithm
      header[:alg]
    end

    def digest
      OpenSSL::Digest::Digest.new "SHA#{algorithm.to_s[2, 3]}"
    end

    def hmac?
      [:HS256, :HS384, :HS512].collect(&:to_s).include? algorithm.to_s
    end

    def rsa?
      [:RS256, :RS384, :RS512].collect(&:to_s).include? algorithm.to_s
    end

    def ecdsa?
      [:ES256, :ES384, :ES512].collect(&:to_s).include? algorithm.to_s
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
      case
      when hmac?
        secret = private_key_or_secret
        OpenSSL::HMAC.digest digest, secret, signature_base_string
      when rsa?
        private_key = private_key_or_secret
        private_key.sign digest, signature_base_string
      when ecdsa?
        private_key = private_key_or_secret
        verify_ecdsa_group! private_key
        private_key.dsa_sign_asn1 digest.digest(signature_base_string)
      else
        raise InvalidFormat.new('Unknown Signature Algorithm')
      end
    end

    def valid?(signature_base_string, signature, public_key_or_secret)
      case
      when hmac?
        secret = public_key_or_secret
        sign(signature_base_string, secret) == signature
      when rsa?
        public_key = public_key_or_secret
        public_key.verify digest, signature, signature_base_string
      when ecdsa?
        public_key = public_key_or_secret
        verify_ecdsa_group! public_key
        public_key.dsa_verify_asn1 digest.digest(signature_base_string), signature
      else
        raise InvalidFormat.new('Unknown Signature Algorithm')
      end
    end

    def verify_ecdsa_group!(key)
      group_name = case digest.digest_length * 8
      when 256
        'secp256k1'
      when 384
        'secp384r1'
      when 512
        'secp521r1'
      end
      key.group = OpenSSL::PKey::EC::Group.new group_name
      key.check_key
    end

    def replace(hash_or_jwt)
      super
      if hash_or_jwt.is_a? JSON::JWT
        self.header = hash_or_jwt.header
        self.signature = hash_or_jwt.signature
      end
      self
    end
  end
end
