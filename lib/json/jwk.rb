module JSON
  class JWK < ActiveSupport::HashWithIndifferentAccess
    class UnknownAlgorithm < JWT::Exception; end

    def content_type
      'application/jwk+json'
    end

    def thumbprint(digest = OpenSSL::Digest::SHA256.new)
      digest = case digest
      when OpenSSL::Digest
        digest
      when String, Symbol
        OpenSSL::Digest.new digest.to_s
      else
        raise UnknownAlgorithm.new('Unknown Digest Algorithm')
      end
      UrlSafeBase64.encode64 digest.digest(normalize.to_json)
    end

    def to_key
      case self[:kty].try(:to_sym)
      when :RSA
        e = OpenSSL::BN.new UrlSafeBase64.decode64(self[:e]), 2
        n = OpenSSL::BN.new UrlSafeBase64.decode64(self[:n]), 2
        key = OpenSSL::PKey::RSA.new
        key.e = e
        key.n = n
        key.d = d if d
        key
      when :EC
        key = OpenSSL::PKey::EC.new full_curve_name
        x, y = [self[:x], self[:y]].collect do |decoded|
          OpenSSL::BN.new UrlSafeBase64.decode64(decoded), 2
        end
        key.public_key = OpenSSL::PKey::EC::Point.new(key.group).mul(x, y)
        key
      else
        raise UnknownAlgorithm.new('Unknown Key Type')
      end
    end

    private

    def normalize
      case self[:kty].try(:to_sym)
      when :RSA
        {
          e: self[:e],
          kty: self[:kty],
          n: self[:n]
        }
      when :EC
        {
          crv: self[:crv],
          kty: self[:kty],
          x: self[:x],
          y: self[:y]
        }
      else
        raise UnknownAlgorithm.new('Unknown Key Type')
      end
    end

    def full_curve_name
      case self[:crv].try(:to_sym)
      when :'P-256'
        'prime256v1'
      when :'P-384'
        'secp384r1'
      when :'P-521'
        'secp521r1'
      else
        raise UnknownAlgorithm.new('Unknown ECDSA Curve')
      end
    end
  end
end