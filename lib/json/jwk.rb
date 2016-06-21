module JSON
  class JWK < ActiveSupport::HashWithIndifferentAccess
    class UnknownAlgorithm < JWT::Exception; end

    def initialize(params = {}, ex_params = {})
      case params
      when OpenSSL::PKey::RSA, OpenSSL::PKey::EC
        super params.to_jwk(ex_params)
      when OpenSSL::PKey::PKey
        raise UnknownAlgorithm.new('Unknown Key Type')
      when String
        super(
          k: params,
          kty: :oct
        )
        merge! ex_params
      else
        super params
        merge! ex_params
      end
    end

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
      case
      when rsa?
        to_rsa_key
      when ec?
        to_ec_key
      when oct?
        self[:k]
      else
        raise UnknownAlgorithm.new('Unknown Key Type')
      end
    end

    private

    def rsa?
      self[:kty].try(:to_sym) == :RSA
    end

    def ec?
      self[:kty].try(:to_sym) == :EC
    end

    def oct?
      self[:kty].try(:to_sym) == :oct
    end

    def normalize
      case
      when rsa?
        {
          e:   self[:e],
          kty: self[:kty],
          n:   self[:n]
        }
      when ec?
        {
          crv: self[:crv],
          kty: self[:kty],
          x:   self[:x],
          y:   self[:y]
        }
      when oct?
        {
          k:   self[:k],
          kty: self[:kty]
        }
      else
        raise UnknownAlgorithm.new('Unknown Key Type')
      end
    end

    def to_rsa_key
      e, n, d, p, q = [:e, :n, :d, :p, :q].collect do |key|
        if self[key]
          OpenSSL::BN.new UrlSafeBase64.decode64(self[key]), 2
        end
      end
      key = OpenSSL::PKey::RSA.new
      key.e = e
      key.n = n
      key.d = d if d
      key.p = p if p
      key.q = q if q
      key
    end

    def to_ec_key
      curve_name = case self[:crv].try(:to_sym)
      when :'P-256'
        'prime256v1'
      when :'P-384'
        'secp384r1'
      when :'P-521'
        'secp521r1'
      else
        raise UnknownAlgorithm.new('Unknown EC Curve')
      end
      x, y, d = [:x, :y, :d].collect do |key|
        if self[key]
          OpenSSL::BN.new UrlSafeBase64.decode64(self[key]), 2
        end
      end
      key = OpenSSL::PKey::EC.new curve_name
      key.private_key = d if d
      key.public_key = OpenSSL::PKey::EC::Point.new(
        OpenSSL::PKey::EC::Group.new(curve_name),
        OpenSSL::BN.new(['04' + x.to_s(16) + y.to_s(16)].pack('H*'), 2)
      )
      key
    end
  end
end