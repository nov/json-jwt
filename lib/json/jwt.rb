require 'openssl'
require 'url_safe_base64'
require 'json'
require 'active_support/core_ext'

module JSON
  class JWT < Hash
    attr_accessor :header, :signature

    class Exception < StandardError; end
    class InvalidFormat < Exception; end
    class VerificationFailed < Exception; end
    class UnexpectedAlgorithm < VerificationFailed; end

    def initialize(claims)
      @header = {
        :typ => :JWT,
        :alg => :none
      }
      [:exp, :nbf, :iat].each do |key|
        claims[key] = claims[key].to_i if claims[key]
      end
      replace claims
    end

    def sign(private_key_or_secret, algorithm = :HS256)
      header[:alg] = algorithm
      JWS.new(self).sign!(private_key_or_secret)
    end

    def verify(signature_base_string, signature = '', public_key_or_secret = nil)
      if header[:alg].to_s == 'none'
        raise UnexpectedAlgorithm if public_key_or_secret
        signature == '' or raise VerificationFailed
      else
        JWS.new(self).verify(signature_base_string, signature, public_key_or_secret)
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

    class << self
      def decode(jwt_string, key_or_secret = nil)
        case jwt_string.count('.')
        when 2 # JWT / JWS
          header, claims, signature = jwt_string.split('.', 3).collect do |segment|
            UrlSafeBase64.decode64 segment.to_s
          end
          signature_base_string = jwt_string.split('.')[0, 2].join('.')
          jwt = new JSON.parse(claims, :symbolize_names => true, :symbolize_keys => true)
          jwt.header = JSON.parse(header, :symbolize_names => true, :symbolize_keys => true)
          jwt.verify signature_base_string, signature, key_or_secret
          jwt
        when 3 # JWE
          # TODO: Concept code first.
          #  jwt = JWE.decrypt ...
          #  jwt.verify ...
        else
          raise InvalidFormat.new('Invalid JWT Format. JWT should include 2 or 3 dots.')
        end
      rescue JSON::ParserError
        raise InvalidFormat.new("Invalid JSON Format")
      end
    end
  end
end

require 'json/jws'
require 'json/jwe'
require 'json/jwk'
