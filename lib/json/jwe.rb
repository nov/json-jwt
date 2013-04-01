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

    def encrypted_key
      unless @encrypted_key
        @encrypted_key = case algorithm.to_s
        when :RSA1_5.to_s
        when :'RSA-OAEP'.to_s
        when :A128KW .to_s
        when :A256KW.to_s
        when :dir.to_s
          ''
        when :'ECDH-ES'.to_s
        when :'ECDH-ES+A128KW'.to_s
        when :'ECDH-ES+A256KW'.to_s
        else
          raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
        end
      end
      @encrypted_key
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

    def algorithm_pair # remove later
      [algorithm, encryption_method]
    end

    def rsa_oaep_a256gcm? # remove later
      [:'RSA-OAEP', :A256GCM].collect(&:to_s) == algorithm_pair.collect(&:to_s)
    end

    def rsa1_5_a128cbc_hs256? # remove later
      [:RSA1_5, :'A128CBC+HS256'].collect(&:to_s) == algorithm_pair.collect(&:to_s)
    end

    def a128kw_a128gcm? # remove later
      [:A128KW, :A128GCM].collect(&:to_s) == algorithm_pair.collect(&:to_s)
    end

    def rsa_oaep_a256gcm(public_key) # remove later
      if RUBY_VERSION >= '2.0' && OpenSSL::OPENSSL_VERSION >= 'OpenSSL 1.0.1c'
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        raw_key = cipher.random_key
        self.iv = cipher.random_iv
        self.key = public_key.public_encrypt raw_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        cipher.auth_data = [header.to_json, key, iv].collect do |segment|
          UrlSafeBase64.encode64 segment.to_s
        end.join('.')
        self.cipher_text = cipher.update(plain_text) + cipher.final
        self.integrity_value = cipher.auth_tag
        self
      else
        raise UnexpectedAlgorithm.new('AES256GCM requires Ruby 2.0+ and OpenSSL 1.0.1c+')
      end
    end

    def rsa1_5_a128cbc_hs256(public_key) # remove later
      raise NotImplementedError.new('RSA1_5 A128CBC+HS256 not implemented yet')
    end

    def a128kw_a128gcm(secret) # remove later
      raise NotImplementedError.new('A128KW A128GCM not implemented yet')
    end
  end
end