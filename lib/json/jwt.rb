require 'openssl'
require 'url_safe_base64'
require 'multi_json'
require 'active_support'
require 'active_support/core_ext'
require 'json/jose'

module JSON
  class JWT < ActiveSupport::HashWithIndifferentAccess
    attr_accessor :signature

    class Exception < StandardError; end
    class InvalidFormat < Exception; end
    class VerificationFailed < Exception; end
    class UnexpectedAlgorithm < VerificationFailed; end

    include JOSE

    def initialize(claims = {})
      @content_type = 'application/jwt'
      self.typ = :JWT
      self.alg = :none
      [:exp, :nbf, :iat].each do |key|
        claims[key] = claims[key].to_i if claims[key]
      end
      update claims
    end

    def sign(private_key_or_secret, algorithm = :HS256)
      # NOTE: needs to set "kid" before generating JWS signature base string
      self.kid ||= private_key_or_secret[:kid] if private_key_or_secret.is_a? JSON::JWK
      jws = JWS.new self
      jws.alg = algorithm
      jws.sign! private_key_or_secret
    end

    def encrypt(public_key_or_secret, algorithm = :RSA1_5, encryption_method = :'A128CBC-HS256')
      # NOTE: needs to set "kid" before generating JWE plain text
      self.kid ||= public_key_or_secret[:kid] if public_key_or_secret.is_a? JSON::JWK
      jwe = JWE.new self
      jwe.alg = algorithm
      jwe.enc = encryption_method
      jwe.encrypt! public_key_or_secret
    end

    def to_s
      [
        header.to_json,
        self.to_json,
        signature
      ].collect do |segment|
        UrlSafeBase64.encode64 segment.to_s
      end.join('.')
    end

    def as_json(options = {})
      case options[:syntax]
      when :general
        {
          payload: UrlSafeBase64.encode64(self.to_json),
          signatures: [{
            protected: UrlSafeBase64.encode64(header.to_json),
            signature: UrlSafeBase64.encode64(signature.to_s)
          }]
        }
      when :flattened
        {
          protected: UrlSafeBase64.encode64(header.to_json),
          payload:   UrlSafeBase64.encode64(self.to_json),
          signature: UrlSafeBase64.encode64(signature.to_s)
        }
      else
        super
      end
    end

    class << self
      def decode_compact_serialized(jwt_string, key_or_secret)
        case jwt_string.count('.') + 1
        when JWS::NUM_OF_SEGMENTS
          JWS.decode_compact_serialized jwt_string, key_or_secret
        when JWE::NUM_OF_SEGMENTS
          JWE.decode_compact_serialized jwt_string, key_or_secret
        else
          raise InvalidFormat.new("Invalid JWT Format. JWT should include #{JWS::NUM_OF_SEGMENTS} or #{JWE::NUM_OF_SEGMENTS} segments.")
        end
      end

      def decode_json_serialized(input, key_or_secret)
        input = input.with_indifferent_access
        if (input[:signatures] || input[:signature]).present?
          JWS.decode_json_serialized input, key_or_secret
        elsif input[:ciphertext].present?
          JWE.decode_json_serialized input, key_or_secret
        else
          raise InvalidFormat.new("Unexpected JOSE JSON Serialization Format.")
        end
      end
    end
  end
end

require 'json/jws'
require 'json/jwe'
require 'json/jwk'
require 'json/jwk/jwkizable'
require 'json/jwk/set'