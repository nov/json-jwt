require 'openssl'
require 'base64'
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

    def sign(private_key_or_secret, algorithm = :autodetect)
      jws = JWS.new self
      jws.kid ||= private_key_or_secret[:kid] if private_key_or_secret.is_a? JSON::JWK
      jws.alg = algorithm
      jws.sign! private_key_or_secret
    end

    def encrypt(public_key_or_secret, algorithm = :RSA1_5, encryption_method = :'A128CBC-HS256')
      jwe = JWE.new self
      jwe.kid ||= public_key_or_secret[:kid] if public_key_or_secret.is_a? JSON::JWK
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
        Base64.urlsafe_encode64 segment.to_s, padding: false
      end.join('.')
    end

    def as_json(options = {})
      case options[:syntax]
      when :general
        {
          payload: Base64.urlsafe_encode64(self.to_json, padding: false),
          signatures: [{
            protected: Base64.urlsafe_encode64(header.to_json, padding: false),
            signature: Base64.urlsafe_encode64(signature.to_s, padding: false)
          }]
        }
      when :flattened
        {
          protected: Base64.urlsafe_encode64(header.to_json, padding: false),
          payload:   Base64.urlsafe_encode64(self.to_json, padding: false),
          signature: Base64.urlsafe_encode64(signature.to_s, padding: false)
        }
      else
        super
      end
    end

    def pretty_generate
      [
        JSON.pretty_generate(header),
        JSON.pretty_generate(self)
      ]
    end

    class << self
      def decode_compact_serialized(jwt_string, key_or_secret, algorithms = nil, encryption_methods = nil)
        case jwt_string.count('.') + 1
        when JWS::NUM_OF_SEGMENTS
          JWS.decode_compact_serialized jwt_string, key_or_secret, algorithms
        when JWE::NUM_OF_SEGMENTS
          JWE.decode_compact_serialized jwt_string, key_or_secret, algorithms, encryption_methods
        else
          raise InvalidFormat.new("Invalid JWT Format. JWT should include #{JWS::NUM_OF_SEGMENTS} or #{JWE::NUM_OF_SEGMENTS} segments.")
        end
      end

      def decode_json_serialized(input, key_or_secret, algorithms = nil, encryption_methods = nil)
        input = input.with_indifferent_access
        if (input[:signatures] || input[:signature]).present?
          JWS.decode_json_serialized input, key_or_secret, algorithms
        elsif input[:ciphertext].present?
          JWE.decode_json_serialized input, key_or_secret, algorithms, encryption_methods
        else
          raise InvalidFormat.new("Unexpected JOSE JSON Serialization Format.")
        end
      end

      def pretty_generate(jwt_string)
        decode(jwt_string, :skip_verification).pretty_generate
      end
    end
  end
end

require 'json/jws'
require 'json/jwe'
require 'json/jwk'
require 'json/jwk/jwkizable'
require 'json/jwk/set'
