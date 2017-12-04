require 'securecompare'

module JSON
  module JOSE
    extend ActiveSupport::Concern

    included do
      extend ClassMethods
      include SecureCompare
      register_header_keys :alg, :jku, :jwk, :x5u, :x5t, :x5c, :kid, :typ, :cty, :crit
      alias_method :algorithm, :alg

      attr_accessor :header
      def header
        @header ||= {}
      end

      def content_type
        @content_type ||= 'application/jose'
      end
    end

    def with_jwk_support(key)
      case key
      when JSON::JWK
        key.to_key
      when JSON::JWK::Set
        key.detect do |jwk|
          jwk[:kid] && jwk[:kid] == kid
        end.try(:to_key) or raise JWK::Set::KidNotFound
      else
        key
      end
    end

    module ClassMethods
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

      def decode(input, key_or_secret = nil, algorithms = nil, encryption_methods = nil)
        if input.is_a? Hash
          decode_json_serialized input, key_or_secret, algorithms, encryption_methods
        else
          decode_compact_serialized input, key_or_secret, algorithms, encryption_methods
        end
      rescue JSON::ParserError
        raise JWT::InvalidFormat.new("Invalid JSON Format")
      end
    end
  end
end