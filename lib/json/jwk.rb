module JSON
  class JWK < Hash
    class UnknownAlgorithm < JWT::Exception; end

    def initialize(public_key, options = {})
      replace encode(public_key, options)
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
          :y => hex_y
        }
      end
      @ecdsa_coodinates
    end

    def encode(public_key, options = {})
      hash = case public_key
      when OpenSSL::PKey::RSA
        {
          :alg => :RSA,
          :exp => UrlSafeBase64.encode64(public_key.e.to_s(2)),
          :mod => UrlSafeBase64.encode64(public_key.n.to_s(2))
        }
      when OpenSSL::PKey::EC
        {
          :alg => :EC,
          :crv => ecdsa_curve_name(public_key),
          :x => UrlSafeBase64.encode64(ecdsa_coodinates(public_key)[:x].to_s),
          :y => UrlSafeBase64.encode64(ecdsa_coodinates(public_key)[:y].to_s)
        }
      else
        raise UnknownAlgorithm.new('Unknown Algorithm')
      end
      hash.merge(options)
    end
  end
end

require 'json/jwk/set'
