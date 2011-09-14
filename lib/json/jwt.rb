require 'openssl'
require 'url_safe_base64'
require 'json'

module JSON
  class JWT < Hash
    attr_accessor :header, :signature

    def initialize(claim)
      @header = {
        :typ => :JWT,
        :alg => :none
      }
      [:exp, :nbf, :iat].each do |key|
        if claim[key]
          claim[key] = claim[key].to_i
        end
      end
      relpace claim
    end

    def sign(private_key_or_secret, algorithm = :RS256)
      JWS.new(self).sign(private_key_or_secret, algorithm)
    end

    def to_s
      [
        header.to_json,
        self.to_json,
        signature
      ].collect do |segment|
        UrlSafeBase64.encode64 segment
      end.join('.')
    end
  end
end

require 'json/jws'
require 'json/jwe'