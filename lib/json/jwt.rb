require 'openssl'
require 'url_safe_base64'
require 'multi_json'
require 'active_support/core_ext'

module JSON
  class JWT < HashWithIndifferentAccess
    attr_accessor :header, :signature

    class Exception < StandardError; end
    class InvalidFormat < Exception; end
    class VerificationFailed < Exception; end
    class UnexpectedAlgorithm < VerificationFailed; end

    def header
      @header ||= {}
    end

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
    register_header_keys :typ, :cty, :alg
    alias_method :algorithm, :alg

    def initialize(claims)
      self.typ = :JWT
      self.alg = :none
      [:exp, :nbf, :iat].each do |key|
        claims[key] = claims[key].to_i if claims[key]
      end
      replace claims
    end

    def sign(private_key_or_secret, algorithm = :HS256)
      jws = JWS.new(self)
      jws.alg = algorithm
      jws.sign! private_key_or_secret
    end

    def verify(signature_base_string, public_key_or_secret = nil)
      if alg.to_s == 'none'
        raise UnexpectedAlgorithm if public_key_or_secret
        signature == '' or raise VerificationFailed
      else
        JWS.new(self).verify(signature_base_string, public_key_or_secret)
      end
    end

    def encrypt(public_key_or_secret, algorithm = :RSA1_5, encryption_method = :'A128CBC+HS256')
      jwe = JWE.new(self)
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

    class << self
      def decode(jwt_string, key_or_secret = nil)
        case jwt_string.count('.')
        when 2 # JWT / JWS
          header, claims, signature = jwt_string.split('.', 3).collect do |segment|
            UrlSafeBase64.decode64 segment.to_s
          end
          header, claims = [header, claims].collect do |json|
            MultiJson.load(json).with_indifferent_access
          end
          signature_base_string = jwt_string.split('.')[0, 2].join('.')
          jwt = new claims
          jwt.header = header
          jwt.signature = signature

          # NOTE:
          #  Some JSON libraries generates wrong format of JSON (spaces between keys and values etc.)
          #  So we need to use raw base64 strings for signature verification.
          jwt.verify signature_base_string, key_or_secret unless key_or_secret == :skip_verification
          jwt
        when 4 # JWE
          jwe = JWE.new jwt_string
          jwe.header = MultiJson.load(
            UrlSafeBase64.decode64 jwt_string.split('.').first
          ).with_indifferent_access
          jwe.decrypt! key_or_secret
        else
          raise InvalidFormat.new('Invalid JWT Format. JWT should include 2 or 3 dots.')
        end
      rescue MultiJson::DecodeError
        raise InvalidFormat.new("Invalid JSON Format")
      end
    end
  end
end

require 'json/jws'
require 'json/jwe'
require 'json/jwk'
