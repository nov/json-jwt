require 'securerandom'

module JSON
  class JWE < JWT
    class InvalidFormat < JWT::InvalidFormat; end
    class DecryptionFailed < JWT::VerificationFailed; end
    class UnexpectedAlgorithm < JWT::UnexpectedAlgorithm; end

    attr_accessor :plain_text, :key, :encrypted_key, :iv, :cipher_text, :integrity_value

    register_header_keys :enc, :epk, :zip, :jku, :jwk, :x5u, :x5t, :x5c, :kid, :typ, :cty, :apu, :apv, :epu, :epv
    alias_method :encryption_method, :enc

    def initialize(jwt_or_plain_text)
      self.plain_text = jwt_or_plain_text.to_s
    end

    def encrypt!(public_key_or_secret)
      cipher.encrypt
      self.encrypted_key = encrypt_key public_key_or_secret
      if gcm?
        cipher.auth_data = [header.to_json, encrypted_key, iv].collect do |segment|
          UrlSafeBase64.encode64 segment.to_s
        end.join('.')
      end
      self.cipher_text = cipher.update(plain_text) + cipher.final
      self
    end

    def encrypt_legacy!(public_key_or_secret) # remove later
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
        encrypted_key,
        iv,
        cipher_text,
        integrity_value
      ].collect do |segment|
        UrlSafeBase64.encode64 segment.to_s
      end.join('.')
    end

    private

    def gcm?
      [:A128GCM, :A256GCM].collect(&:to_s).include? encryption_method.to_s
    end

    def cipher
      unless @cipher
        cipher_name = case encryption_method.to_s
        when :A128GCM.to_s
          :'aes-128-gcm'
        when :A256GCM.to_s
          :'aes-256-gcm'
        when :'A128CBC+HS256'.to_s
          :'aes-128-cbc'
        when :'A256CBC+HS512'.to_s
          :'aes-256-cbc'
        else
          raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
        end
        @cipher = OpenSSL::Cipher.new cipher_name.to_s
        self.key = @cipher.random_key
        self.iv = @cipher.random_iv
      end
      @cipher
    end

    def encrypt_key(public_key_or_secret)
      case algorithm.to_s
      when :RSA1_5.to_s
        public_key_or_secret.public_encrypt key
      when :'RSA-OAEP'.to_s
        public_key_or_secret.public_encrypt key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      when :A128KW .to_s
        raise NotImplementedError.new('A128KW not implemented yet')
      when :A256KW.to_s
        raise NotImplementedError.new('A256KW not implemented yet')
      when :dir.to_s
        ''
      when :'ECDH-ES'.to_s
        raise NotImplementedError.new('ECDH-ES not implemented yet')
      when :'ECDH-ES+A128KW'.to_s
        raise NotImplementedError.new('ECDH-ES+A128KW not implemented yet')
      when :'ECDH-ES+A256KW'.to_s
        raise NotImplementedError.new('ECDH-ES+A256KW not implemented yet')
      else
        raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
      end
    end

    def integrity_value
      unless @integrity_value
        @integrity_value = if gcm?
          cipher.auth_tag
        else
          # TODO
        end
      end
      @integrity_value
    end
  end
end