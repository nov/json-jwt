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
      calculate_default_kid if self[:kid].blank?
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
      Base64.urlsafe_encode64 digest.digest(normalize.to_json), padding: false
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

    def rsa?
      self[:kty]&.to_sym == :RSA
    end

    def ec?
      self[:kty]&.to_sym == :EC
    end

    def oct?
      self[:kty]&.to_sym == :oct
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

    private

    def calculate_default_kid
      self[:kid] = thumbprint
    rescue
      # ignore
    end

    def to_rsa_key
      e, n, d, p, q, dp, dq, qi = [:e, :n, :d, :p, :q, :dp, :dq, :qi].collect do |key|
        if self[key]
          OpenSSL::BN.new Base64.urlsafe_decode64(self[key]), 2
        end
      end

      # Public key
      data_sequence = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(n),
        OpenSSL::ASN1::Integer(e),
      ])

      if d && p && q && dp && dq && qi
        data_sequence = OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer(0),
          OpenSSL::ASN1::Integer(n),
          OpenSSL::ASN1::Integer(e),
          OpenSSL::ASN1::Integer(d),
          OpenSSL::ASN1::Integer(p),
          OpenSSL::ASN1::Integer(q),
          OpenSSL::ASN1::Integer(dp),
          OpenSSL::ASN1::Integer(dq),
          OpenSSL::ASN1::Integer(qi),
        ])
      end

      asn1 = OpenSSL::ASN1::Sequence(data_sequence)
      OpenSSL::PKey::RSA.new(asn1.to_der)
    end

    def to_ec_key
      curve_name = case self[:crv]&.to_sym
      when :'P-256'
        'prime256v1'
      when :'P-384'
        'secp384r1'
      when :'P-521'
        'secp521r1'
      when :secp256k1
        'secp256k1'
      else
        raise UnknownAlgorithm.new('Unknown EC Curve')
      end
      x, y, d = [:x, :y, :d].collect do |key|
        if self[key]
          Base64.urlsafe_decode64(self[key])
        end
      end

      point = OpenSSL::PKey::EC::Point.new(
        OpenSSL::PKey::EC::Group.new(curve_name),
        OpenSSL::BN.new(['04' + x.unpack('H*').first + y.unpack('H*').first].pack('H*'), 2)
      )

      # Public key
      data_sequence = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
          OpenSSL::ASN1::ObjectId(curve_name)
        ]),
        OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
      ])

      if d
        # Private key
        data_sequence = OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer(1),
          OpenSSL::ASN1::OctetString(OpenSSL::BN.new(d, 2).to_s(2)),
          OpenSSL::ASN1::ObjectId(curve_name, 0, :EXPLICIT),
          OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed), 1, :EXPLICIT)
        ])
      end

      OpenSSL::PKey::EC.new(data_sequence.to_der)
    end
  end
end
