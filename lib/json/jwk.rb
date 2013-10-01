module JSON
  class JWK < ActiveSupport::HashWithIndifferentAccess
    class UnknownAlgorithm < JWT::Exception; end

    def initialize(public_key, options = {})
      replace encode(public_key, options)
    end

    def content_type
      'application/jwk+json'
    end

    private

    def ecdsa_curve_name(ecdsa_key)
      case ecdsa_key.group.curve_name
      when 'secp256k1'
        :'P-256'
      when 'secp384r1'
        :'P-384'
      when 'secp521r1'
        :'P-521'
      else
        raise UnknownAlgorithm.new('Unknown ECDSA Curve')
      end
    end

    def ecdsa_coodinates(ecdsa_key)
      unless @ecdsa_coodinates
        hex = ecdsa_key.public_key.to_bn.to_s(16)
        data_len = hex.length - 2
        type = hex[0,2]
        hex_x =  hex[2, data_len/2]
        hex_y = hex[2+data_len/2, data_len/2]
        @ecdsa_coodinates = {
          :x => hex_x,
          :y => hex_y,
        }
      end
      @ecdsa_coodinates
    end

    def encode(public_key, options = {})
      hash = case public_key
      when OpenSSL::PKey::RSA
        {
          :kty => :RSA,
          :e   => UrlSafeBase64.encode64(public_key.e.to_s(2)),
          :n   => UrlSafeBase64.encode64(public_key.n.to_s(2)),
        }
      when OpenSSL::PKey::EC
        {
          :kty => :EC,
          :crv => ecdsa_curve_name(public_key),
          :x   => UrlSafeBase64.encode64(ecdsa_coodinates(public_key)[:x].to_s),
          :y   => UrlSafeBase64.encode64(ecdsa_coodinates(public_key)[:y].to_s),
        }
      else
        raise UnknownAlgorithm.new('Unknown Algorithm')
      end
      hash.merge(options)
    end

    class << self
      def decode(jwk)
        jwk = jwk.with_indifferent_access
        case jwk[:kty].to_s
        when 'RSA'
          e = OpenSSL::BN.new UrlSafeBase64.decode64(jwk[:e]), 2
          n = OpenSSL::BN.new UrlSafeBase64.decode64(jwk[:n]), 2
          key = OpenSSL::PKey::RSA.new
          key.e = e
          key.n = n
          key
        when 'EC'
          raise NotImplementedError.new('Not Implemented Yet')
        else
          raise UnknownAlgorithm.new('Unknown Algorithm')
        end
      end

      # NOTE: Ugly hack to avoid this ActiveSupport 4.0 bug.
      #  https://github.com/rails/rails/issues/11087
      def new_from_hash_copying_default(hash)
        superclass.new_from_hash_copying_default hash
      end
    end
  end
end

require 'json/jwk/set'
