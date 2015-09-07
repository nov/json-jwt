require 'securerandom'
require 'bindata'

module JSON
  class JWE < JOSE
    class InvalidFormat < JWT::InvalidFormat; end
    class DecryptionFailed < JWT::VerificationFailed; end
    class UnexpectedAlgorithm < JWT::UnexpectedAlgorithm; end

    NUM_OF_SEGMENTS = 5

    attr_accessor(
      :public_key_or_secret, :private_key_or_secret, :mode,
      :input, :plain_text, :cipher_text, :authentication_tag, :iv,
      :content_encryption_key, :jwe_encrypted_key, :encryption_key, :mac_key
    )

    register_header_keys :enc, :epk, :zip, :apu, :apv
    alias_method :encryption_method, :enc

    def initialize(input)
      self.input = input
    end

    def content_type
      'application/jose'
    end

    def encrypt!(public_key_or_secret)
      self.mode = :encryption
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
      decode_segments!
      cipher.decrypt
      restore_cipher_keys!
      self.plain_text = cipher.update(cipher_text) + cipher.final
      verify_cbc_authentication_tag! if cbc?
      self
    end

    def input=(_input_)
      @input = _input_.to_s
      update _input_ if _input_.is_a? JSON::JWT
    end

    def to_s
      if mode == :encryption
        [
          header.to_json,
          jwe_encrypted_key,
          iv,
          cipher_text,
          authentication_tag
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
      RUBY_VERSION >= '2.0.0' && OpenSSL::OPENSSL_VERSION >= 'OpenSSL 1.0.1'
    end

    def gcm?
      [:A128GCM, :A256GCM].include? encryption_method.try(:to_sym)
    end

    def cbc?
      [:'A128CBC-HS256', :'A256CBC-HS512'].include? encryption_method.try(:to_sym)
    end

    def dir?
      :dir == algorithm.try(:to_sym)
    end

    def cipher
      @cipher ||= if gcm? && !gcm_supported?
        raise UnexpectedAlgorithm.new('AEC GCM requires Ruby 2.0+ and OpenSSL 1.0.1c+') if gcm? && !gcm_supported?
      else
        OpenSSL::Cipher.new cipher_name
      end
    end

    def cipher_name
      case encryption_method.try(:to_sym)
      when :A128GCM
        'aes-128-gcm'
      when :A256GCM
        'aes-256-gcm'
      when :'A128CBC-HS256'
        'aes-128-cbc'
      when :'A256CBC-HS512'
        'aes-256-cbc'
      else
        raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
      end
    end

    def sha_size
      case encryption_method.try(:to_sym)
      when :'A128CBC-HS256'
        256
      when :'A256CBC-HS512'
        512
      else
        raise UnexpectedAlgorithm.new('Unknown Hash Size')
      end
    end

    def sha_digest
      OpenSSL::Digest.new "SHA#{sha_size}"
    end

    def derive_encryption_and_mac_keys_cbc!
      self.mac_key, self.encryption_key = content_encryption_key.unpack("a#{content_encryption_key.length / 2}" * 2)
      self
    end

    def derive_encryption_and_mac_keys_gcm!
      self.encryption_key = content_encryption_key
      self.mac_key = :wont_be_used
      self
    end

    # encryption

    def jwe_encrypted_key
      @jwe_encrypted_key ||= case algorithm.try(:to_sym)
      when :RSA1_5
        public_key_or_secret.public_encrypt content_encryption_key
      when :'RSA-OAEP'
        public_key_or_secret.public_encrypt content_encryption_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      when :A128KW
        raise NotImplementedError.new('A128KW not supported yet')
      when :A256KW
        raise NotImplementedError.new('A256KW not supported yet')
      when :dir
        ''
      when :'ECDH-ES'
        raise NotImplementedError.new('ECDH-ES not supported yet')
      when :'ECDH-ES+A128KW'
        raise NotImplementedError.new('ECDH-ES+A128KW not supported yet')
      when :'ECDH-ES+A256KW'
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
      cipher.key = encryption_key
      self.iv = cipher.random_iv
      if gcm?
        cipher.auth_data = UrlSafeBase64.encode64 header.to_json
      end
      self
    end

    def generate_gcm_keys!
      self.content_encryption_key ||= if dir?
        public_key_or_secret
      else
        cipher.random_key
      end
      derive_encryption_and_mac_keys_gcm!
      self
    end

    def generate_cbc_keys!
      self.content_encryption_key ||= if dir?
        public_key_or_secret
      else
        SecureRandom.random_bytes sha_size / 8
      end
      derive_encryption_and_mac_keys_cbc!
      self
    end

    def authentication_tag
      @authentication_tag ||= case
      when gcm?
        cipher.auth_tag
      when cbc?
        auth_data = UrlSafeBase64.encode64 header.to_json
        secured_input = [
          auth_data,
          iv,
          cipher_text,
          BinData::Uint64be.new(auth_data.length * 8).to_binary_s
        ].join
        OpenSSL::HMAC.digest(
          sha_digest, mac_key, secured_input
        )[0, sha_size / 2 / 8]
      end
    end

    # decryption

    def decode_segments!
      unless input.count('.') + 1 == NUM_OF_SEGMENTS
        raise InvalidFormat.new("Invalid JWE Format. JWE should include #{NUM_OF_SEGMENTS} segments.")
      end
      _header_json_, self.jwe_encrypted_key, self.iv, self.cipher_text, self.authentication_tag = input.split('.').collect do |segment|
        UrlSafeBase64.decode64 segment
      end
      self
    end

    def decrypt_content_encryption_key
      case algorithm.try(:to_sym)
      when :RSA1_5
        private_key_or_secret.private_decrypt jwe_encrypted_key
      when :'RSA-OAEP'
        private_key_or_secret.private_decrypt jwe_encrypted_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      when :A128KW
        raise NotImplementedError.new('A128KW not supported yet')
      when :A256KW
        raise NotImplementedError.new('A256KW not supported yet')
      when :dir
        private_key_or_secret
      when :'ECDH-ES'
        raise NotImplementedError.new('ECDH-ES not supported yet')
      when :'ECDH-ES+A128KW'
        raise NotImplementedError.new('ECDH-ES+A128KW not supported yet')
      when :'ECDH-ES+A256KW'
        raise NotImplementedError.new('ECDH-ES+A256KW not supported yet')
      else
        raise UnexpectedAlgorithm.new('Unknown Encryption Algorithm')
      end
    end

    def restore_cipher_keys!
      self.content_encryption_key = decrypt_content_encryption_key
      case
      when gcm?
        derive_encryption_and_mac_keys_gcm!
      when cbc?
        derive_encryption_and_mac_keys_cbc!
      end
      cipher.key = encryption_key
      cipher.iv = iv # NOTE: 'iv' has to be set after 'key' for GCM
      if gcm?
        cipher.auth_tag = authentication_tag
        cipher.auth_data = input.split('.').first
      end
    end

    def verify_cbc_authentication_tag!
      auth_data = input.split('.').first
      secured_input = [
        auth_data,
        iv,
        cipher_text,
        BinData::Uint64be.new(auth_data.length * 8).to_binary_s
      ].join
      expected_authentication_tag = OpenSSL::HMAC.digest(
        sha_digest, mac_key, secured_input
      )[0, sha_size / 2 / 8]
      unless secure_compare(authentication_tag, expected_authentication_tag)
        raise DecryptionFailed.new('Invalid authentication tag')
      end
    end
  end
end