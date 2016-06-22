require 'securerandom'
require 'bindata'

module JSON
  class JWE
    class InvalidFormat < JWT::InvalidFormat; end
    class DecryptionFailed < JWT::VerificationFailed; end
    class UnexpectedAlgorithm < JWT::UnexpectedAlgorithm; end

    NUM_OF_SEGMENTS = 5

    include JOSE

    attr_accessor(
      :public_key_or_secret, :private_key_or_secret,
      :plain_text, :cipher_text, :authentication_tag, :iv, :auth_data,
      :content_encryption_key, :jwe_encrypted_key, :encryption_key, :mac_key
    )

    register_header_keys :enc, :epk, :zip, :apu, :apv
    alias_method :encryption_method, :enc

    def initialize(input = nil)
      self.plain_text = input.to_s
    end

    def encrypt!(public_key_or_secret)
      self.public_key_or_secret = with_jwk_support public_key_or_secret
      cipher.encrypt
      generate_cipher_keys!
      self.cipher_text = cipher.update(plain_text) + cipher.final
      self
    end

    def decrypt!(private_key_or_secret)
      self.private_key_or_secret = with_jwk_support private_key_or_secret
      cipher.decrypt
      restore_cipher_keys!
      self.plain_text = cipher.update(cipher_text) + cipher.final
      verify_cbc_authentication_tag! if cbc?
      self
    end

    def to_s
      [
        header.to_json,
        jwe_encrypted_key,
        iv,
        cipher_text,
        authentication_tag
      ].collect do |segment|
        UrlSafeBase64.encode64 segment.to_s
      end.join('.')
    end

    def as_json(options = {})
      case options[:syntax]
      when :general
        {
          protected:  UrlSafeBase64.encode64(header.to_json),
          recipients: [{
            encrypted_key: UrlSafeBase64.encode64(jwe_encrypted_key)
          }],
          iv:         UrlSafeBase64.encode64(iv),
          ciphertext: UrlSafeBase64.encode64(cipher_text),
          tag:        UrlSafeBase64.encode64(authentication_tag)
        }
      else
        {
          protected:     UrlSafeBase64.encode64(header.to_json),
          encrypted_key: UrlSafeBase64.encode64(jwe_encrypted_key),
          iv:            UrlSafeBase64.encode64(iv),
          ciphertext:    UrlSafeBase64.encode64(cipher_text),
          tag:           UrlSafeBase64.encode64(authentication_tag)
        }
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
      self.auth_data = UrlSafeBase64.encode64 header.to_json
      if gcm?
        cipher.auth_data = self.auth_data
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
        cipher.auth_data = auth_data
      end
    end

    def verify_cbc_authentication_tag!
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

    class << self
      def decode_compact_serialized(input, private_key_or_secret)
        unless input.count('.') + 1 == NUM_OF_SEGMENTS
          raise InvalidFormat.new("Invalid JWE Format. JWE should include #{NUM_OF_SEGMENTS} segments.")
        end
        jwe = new
        _header_json_, jwe.jwe_encrypted_key, jwe.iv, jwe.cipher_text, jwe.authentication_tag = input.split('.').collect do |segment|
          UrlSafeBase64.decode64 segment
        end
        jwe.auth_data = input.split('.').first
        jwe.header = MultiJson.load(_header_json_).with_indifferent_access
        jwe.decrypt! private_key_or_secret unless private_key_or_secret == :skip_decryption
        jwe
      end

      def decode_json_serialized(input, private_key_or_secret)
        input = input.with_indifferent_access
        jwe_encrypted_key = if input[:recipients].present?
          input[:recipients].first[:encrypted_key]
        else
          input[:encrypted_key]
        end
        compact_serialized = [
          input[:protected],
          jwe_encrypted_key,
          input[:iv],
          input[:ciphertext],
          input[:tag]
        ].join('.')
        decode_compact_serialized compact_serialized, private_key_or_secret
      end
    end
  end
end