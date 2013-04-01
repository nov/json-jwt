require 'securerandom'

module JSON
  class JWE < JWT
    class InvalidFormat < JWT::InvalidFormat; end
    class DecryptionFailed < JWT::VerificationFailed; end
    class UnexpectedAlgorithm < JWT::UnexpectedAlgorithm; end

    attr_accessor :plain_text, :key, :iv, :cipher_text, :integrity_value

    register_header_keys :enc
    alias_method :encryption_method, :enc

    def initialize(jwt_or_plain_text)
      self.plain_text = jwt_or_plain_text.to_s
    end

    def encrypt!(public_key_or_secret)
      case
      when rsa_oaep_a256gcm?
        public_key = public_key_or_secret
        rsa_oaep_a256gcm public_key
      when rsa1_5_a128cbc_hs256?
        public_key = public_key_or_secret
        rsa1_5_a128cbc_hs256 public_key
      when a128kw_a128gcm?
        secret = public_key_or_secret
        a128kw_a128gcm secret
      else
        if algorithm_pair.any?(&:blank?)
          raise InvalidFormat.new('Encryption Algorithm Required')
        else
          raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
        end
      end
    end

    def to_s
      [
        header.to_json,
        key,
        iv,
        cipher_text,
        integrity_value
      ].collect do |segment|
        UrlSafeBase64.encode64 segment.to_s
      end.join('.')
    end

    private

    def algorithm_pair
      [algorithm, encryption_method]
    end

    def rsa_oaep_a256gcm?
      [:'RSA-OAEP', :A256GCM].collect(&:to_s) == algorithm_pair.collect(&:to_s)
    end

    def rsa1_5_a128cbc_hs256?
      [:RSA1_5, :'A128CBC+HS256'].collect(&:to_s) == algorithm_pair.collect(&:to_s)
    end

    def a128kw_a128gcm?
      [:A128KW, :A128GCM].collect(&:to_s) == algorithm_pair.collect(&:to_s)
    end

    def rsa_oaep_a256gcm(public_key)
      if RUBY_VERSION >= '2.0' && OpenSSL::OPENSSL_VERSION >= 'OpenSSL 1.0.1c'
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        raw_key = cipher.random_key
        self.iv = cipher.random_iv
        self.key = public_key.public_encrypt raw_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        cipher.auth_data = [header, key, iv].collect do |segment|
          UrlSafeBase64.encode64 segment.to_s
        end.join('.')
        self.cipher_text = cipher.update(plain_text) + cipher.final
        self.integrity_value = cipher.auth_tag
        self
      else
        raise UnexpectedAlgorithm.new('AES 256 GCM requires Ruby 2.0+ and OpenSSL 1.0.1c+')
      end
    end

    def rsa1_5_a128cbc_hs256(public_key)
      raise 'define me'
    end

    def a128kw_a128gcm(secret)
      raise 'define me'
    end
  end
end