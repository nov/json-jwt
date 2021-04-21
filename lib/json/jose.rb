require 'active_support/security_utils'

module JSON
  module JOSE
    extend ActiveSupport::Concern

    included do
      extend ClassMethods
      register_header_keys :alg, :jku, :jwk, :x5u, :x5t, :x5c, :kid, :typ, :cty, :crit

      # NOTE: not used anymore in this gem, but keeping in case developers are calling it.
      alias_method :algorithm, :alg

      attr_writer :header
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
        find_key(key)
      else
        key
      end
    end

    def find_key(key)
      if kid
        found_key = key.detect { |jwk| jwk[:kid] && jwk[:kid] == kid }

        return found_key.to_key if found_key

        raise JWK::Set::KidNotFound
      elsif key.length > 1
        raise JWK::Set::KidNotFound
      elsif key.length == 1
        key[0].to_key
      end
    end

    def secure_compare(a, b)
      if ActiveSupport::SecurityUtils.respond_to?(:fixed_length_secure_compare)
        begin
          ActiveSupport::SecurityUtils.fixed_length_secure_compare(a, b)
        rescue ArgumentError
          false
        end
      else
        ActiveSupport::SecurityUtils.secure_compare(a, b)
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

      def decode(input, key_or_secret = nil, algorithms = nil, encryption_methods = nil, allow_blank_payload = false)
        if input.is_a? Hash
          decode_json_serialized input, key_or_secret, algorithms, encryption_methods, allow_blank_payload
        else
          decode_compact_serialized input, key_or_secret, algorithms, encryption_methods, allow_blank_payload
        end
      rescue JSON::ParserError, ArgumentError
        raise JWT::InvalidFormat.new("Invalid JSON Format")
      end
    end
  end
end
