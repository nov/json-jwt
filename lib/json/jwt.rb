require 'openssl'
require 'url_safe_base64'
require 'multi_json'
require 'active_support'
require 'active_support/core_ext'

module JSON
  class JWT < ActiveSupport::HashWithIndifferentAccess
    attr_accessor :header, :signature

    class Exception < StandardError; end
    class InvalidFormat < Exception; end
    class VerificationFailed < Exception; end
    class UnexpectedAlgorithm < VerificationFailed; end

    class << self
      def register_header_keys(*keys)
        keys.each do |header_key|
          define_method header_key do
            self.header[header_key]
          end
          define_method "#{header_key}=" do |value|
            self.header[header_key] = value
          end
        end
      end
    end
    register_header_keys :alg, :jku, :jwk, :x5u, :x5t, :x5c, :kid, :typ, :cty, :crit
    alias_method :algorithm, :alg

    def initialize(claims = {})
      self.typ = :JWT
      self.alg = :none
      [:exp, :nbf, :iat].each do |key|
        claims[key] = claims[key].to_i if claims[key]
      end
      update claims
    end

    def content_type
      'application/jwt'
    end

    def header
      @header ||= {}
    end

    def sign(private_key_or_secret, algorithm = :HS256)
      jws = JWS.new self
      jws.alg = algorithm
      jws.sign! private_key_or_secret
    end

    def encrypt(public_key_or_secret, algorithm = :RSA1_5, encryption_method = :'A128CBC-HS256')
      jwe = JWE.new self
      jwe.alg = algorithm
      jwe.enc = encryption_method
      jwe.encrypt! public_key_or_secret
    end

    # NOTE: keeping for backward compatibility
    def verify(signature_base_string, public_key_or_secret = nil)
      if alg.try(:to_sym) == :none
        raise UnexpectedAlgorithm if public_key_or_secret
        signature == '' or raise VerificationFailed
      else
        JWS.new(self).verify(public_key_or_secret, signature_base_string)
      end
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
      def decode(input, key_or_secret = nil)
        if input.is_a? Hash
          decode_json_serialized input, key_or_secret
        else
          decode_compact_serialized input, key_or_secret
        end
      end

      private

      def decode_compact_serialized(input, key_or_secret = nil)
        case input.count('.') + 1
        when JWS::NUM_OF_SEGMENTS
          JSON::JWS.decode input, key_or_secret
        when JWE::NUM_OF_SEGMENTS
          JSON::JWE.decode input, key_or_secret
        else
          raise InvalidFormat.new("Invalid JWT Format. JWT should include #{JWS::NUM_OF_SEGMENTS} or #{JWE::NUM_OF_SEGMENTS} segments.")
        end
      rescue MultiJson::DecodeError
        raise InvalidFormat.new("Invalid JSON Format")
      end

      def decode_json_serialized(input, key_or_secret = nil)
        input = input.with_indifferent_access
        header, payload, signature = if input[:signatures].present?
          [
            input[:signatures].first[:protected],
            input[:payload],
            input[:signatures].first[:signature]
          ].collect do |segment|
            segment
          end
        else
          [:protected, :payload, :signature].collect do |key|
            input[key]
          end
        end
        jwt_string = [header, payload, signature].join('.')
        decode_compact_serialized jwt_string, key_or_secret
      end
    end
  end
end

require 'json/jose'
require 'json/jws'
require 'json/jwe'
require 'json/jwk'
require 'json/jwk/jwkizable'
require 'json/jwk/set'