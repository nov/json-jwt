require 'securerandom'
require 'bindata'

module JSON
  class JWE < JWT
    class InvalidFormat < JWT::InvalidFormat; end
    class DecryptionFailed < JWT::VerificationFailed; end
    class UnexpectedAlgorithm < JWT::UnexpectedAlgorithm; end

    attr_accessor(
      :public_key_or_secret, :private_key_or_secret, :mode,
      :input, :plain_text, :cipher_text, :integrity_value, :iv,
      :master_key, :encrypted_master_key, :encryption_key, :integrity_key
    )

    register_header_keys :enc, :epk, :zip, :jku, :jwk, :x5u, :x5t, :x5c, :kid, :typ, :cty, :apu, :apv, :epu, :epv
    alias_method :encryption_method, :enc

    def initialize(input)
      self.input = input.to_s
    end

    def encrypt!(public_key_or_secret)
      self.mode = :encyption
      self.plain_text = input
      self.public_key_or_secret = public_key_or_secret
      cipher.encrypt
      generate_cipher_keys!
      self.cipher_text = cipher.update(plain_text) + cipher.final
      self
    end

    def decrypt!(private_key_or_secret)
      self.mode = :decryption
      self.private_key_or_secret = private_key_or_secret
      _header_json_, self.encrypted_master_key, self.iv, self.cipher_text, self.integrity_value = input.split('.').collect do |segment|
        UrlSafeBase64.decode64 segment
      end
      cipher.decrypt
      restore_cipher_keys!
      self.plain_text = cipher.update(cipher_text) + cipher.final
      verify_cbc_integirity_value! if cbc?
      self
    end

    def to_s
      if mode == :encyption
        [
          header.to_json,
          encrypted_master_key,
          iv,
          cipher_text,
          integrity_value
        ].collect do |segment|
          UrlSafeBase64.encode64 segment.to_s
        end.join('.')
      else
        plain_text
      end
    end

    private

    # common

    def gcm_supported?
      RUBY_VERSION >= '2.0.0' && OpenSSL::OPENSSL_VERSION >= 'OpenSSL 1.0.1c'
    end

    def gcm?
      [:A128GCM, :A256GCM].collect(&:to_s).include? encryption_method.to_s
    end

    def cbc?
      [:'A128CBC+HS256', :'A256CBC+HS512'].collect(&:to_s).include? encryption_method.to_s
    end

    def dir?
      :dir.to_s == algorithm.to_s
    end

    def cipher
      @cipher ||= if gcm? && !gcm_supported?
        raise UnexpectedAlgorithm.new('AEC GCM requires Ruby 2.0+ and OpenSSL 1.0.1c+') if gcm? && !gcm_supported?
      else
        OpenSSL::Cipher.new cipher_name
      end
    end

    def cipher_name
      case encryption_method.to_s
      when :A128GCM.to_s
        'aes-128-gcm'
      when :A256GCM.to_s
        'aes-256-gcm'
      when :'A128CBC+HS256'.to_s
        'aes-128-cbc'
      when :'A256CBC+HS512'.to_s
        'aes-256-cbc'
      else
        raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
      end
    end

    def sha_size
      case encryption_method.to_s
      when :'A128CBC+HS256'.to_s
        256
      when :'A256CBC+HS512'.to_s
        512
      else
        raise UnexpectedAlgorithm.new('Unknown Hash Size')
      end
    end

    def sha_digest
      OpenSSL::Digest::Digest.new "SHA#{sha_size}"
    end

    # encyption

    def encrypted_master_key
      @encrypted_master_key ||= case algorithm.to_s
      when :RSA1_5.to_s
        public_key_or_secret.public_encrypt master_key
      when :'RSA-OAEP'.to_s
        public_key_or_secret.public_encrypt master_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      when :A128KW .to_s
        raise NotImplementedError.new('A128KW not supported yet')
      when :A256KW.to_s
        raise NotImplementedError.new('A256KW not supported yet')
      when :dir.to_s
        ''
      when :'ECDH-ES'.to_s
        raise NotImplementedError.new('ECDH-ES not supported yet')
      when :'ECDH-ES+A128KW'.to_s
        raise NotImplementedError.new('ECDH-ES+A128KW not supported yet')
      when :'ECDH-ES+A256KW'.to_s
        raise NotImplementedError.new('ECDH-ES+A256KW not supported yet')
      else
        raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
      end
    end

    def generate_cipher_keys!
      case
      when gcm?
        generate_gcm_keys!
      when cbc?
        generate_cbc_keys!
      end
      @cipher.key = encryption_key
      self.iv = @cipher.random_iv
      if gcm?
        cipher.auth_data = [header.to_json, encrypted_master_key, iv].collect do |segment|
          UrlSafeBase64.encode64 segment.to_s
        end.join('.')
      end
      self
    end

    def generate_gcm_keys!
      self.master_key ||= if dir?
        public_key_or_secret
      else
        @cipher.random_key
      end
      self.encryption_key = master_key
      self.integrity_key = :wont_be_used
      self
    end

    def generate_cbc_keys!
      encryption_key_size = sha_size / 2
      integrity_key_size = master_key_size = sha_size
      self.master_key ||= if dir?
        public_key_or_secret
      else
        SecureRandom.random_bytes master_key_size / 8
      end
      encryption_segments = [
        1,
        master_key,
        encryption_key_size,
        encryption_method,
        epu || 0,
        epv || 0,
        'Encryption'
      ]
      integrity_segments = [
        1,
        master_key,
        integrity_key_size,
        encryption_method,
        epu || 0,
        epv || 0,
        'Integrity'
      ]
      encryption_hash_input, integrity_hash_input = [encryption_segments, integrity_segments].collect do |segments|
        segments.collect do |segment|
          case segment
          when Integer
            BinData::Int32be.new(segment).to_binary_s
          else
            segment.to_s
          end
        end.join
      end
      self.encryption_key = sha_digest.digest(encryption_hash_input)[0, encryption_key_size / 8]
      self.integrity_key = sha_digest.digest integrity_hash_input
      self
    end

    def integrity_value
      @integrity_value ||= case
      when gcm?
        cipher.auth_tag
      when cbc?
        secured_input = [
          header.to_json,
          encrypted_master_key,
          iv,
          cipher_text
        ].collect do |segment|
          UrlSafeBase64.encode64 segment.to_s
        end.join('.')
        OpenSSL::HMAC.digest sha_digest, integrity_key, secured_input
      end
    end

    # decryption

    def decrypt_master_key
      case algorithm.to_s
      when :RSA1_5.to_s
        private_key_or_secret.private_decrypt encrypted_master_key
      when :'RSA-OAEP'.to_s
        private_key_or_secret.private_decrypt encrypted_master_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      when :A128KW .to_s
        raise NotImplementedError.new('A128KW not supported yet')
      when :A256KW.to_s
        raise NotImplementedError.new('A256KW not supported yet')
      when :dir.to_s
        private_key_or_secret
      when :'ECDH-ES'.to_s
        raise NotImplementedError.new('ECDH-ES not supported yet')
      when :'ECDH-ES+A128KW'.to_s
        raise NotImplementedError.new('ECDH-ES+A128KW not supported yet')
      when :'ECDH-ES+A256KW'.to_s
        raise NotImplementedError.new('ECDH-ES+A256KW not supported yet')
      else
        raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
      end
    end

    def restore_cipher_keys!
      self.master_key = decrypt_master_key
      cipher.iv = iv
      case
      when gcm?
        cipher.key = master_key
        cipher.auth_tag = integrity_value
        cipher.auth_data = input.split('.')[0, 3].join('.')
      when cbc?
        restore_cbc_keys!
      end
    end

    def restore_cbc_keys!
      raise UnexpectedAlgorithm.new('TODO')
    end

    def verify_cbc_integirity_value!
      raise UnexpectedAlgorithm.new('TODO')
    end
  end
end