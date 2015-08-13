module JSON
  class JWK < ActiveSupport::HashWithIndifferentAccess
    class UnknownAlgorithm < JWT::Exception; end

    def initialize(constructor = {}, ex_params = {})
      if constructor.is_a? OpenSSL::PKey::PKey
        if constructor.respond_to? :to_jwk
          super constructor.to_jwk(ex_params)
        else
          raise UnknownAlgorithm.new('Unknown Key Type')
        end
      else
        super constructor
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
        if RUBY_VERSION >= '2.0.0'
          to_ec_key
        else
          raise UnknownAlgorithm.new('This feature requires Ruby 2.0+')
        end
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
      else
        raise UnknownAlgorithm.new('Unknown Key Type')
      end
    end

    def to_rsa_key
      e, n, d = [:e, :n, :d].collect do |key|
        if self[key]
          OpenSSL::BN.new UrlSafeBase64.decode64(self[key]), 2
        end
      end
      key = OpenSSL::PKey::RSA.new
      key.e = e
      key.n = n
      key.d = d if d
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
      key = OpenSSL::PKey::EC.new curve_name
      x, y = [self[:x], self[:y]].collect do |decoded|
        OpenSSL::BN.new UrlSafeBase64.decode64(decoded), 2
      end
      key.public_key = OpenSSL::PKey::EC::Point.new(key.group).mul(x, y)
      key
    end

    class << self
      def decode(jwk)
        # NOTE:
        #  returning OpenSSL::PKey::RSA/EC instance for backward compatibility.
        #  use `new` if you want JSON::JWK instance.
        new(jwk).to_key
      end
    end
  end
end