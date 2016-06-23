module JSON
  class JWS < JWT
    class InvalidFormat < JWT::InvalidFormat; end
    class VerificationFailed < JWT::VerificationFailed; end
    class UnexpectedAlgorithm < JWT::UnexpectedAlgorithm; end

    NUM_OF_SEGMENTS = 3

    attr_accessor :signature_base_string

    def initialize(jwt)
      @key_proc = proc {|key| key.to_s }
      update jwt
    end

    def sign!(private_key_or_secret)
      self.signature = sign signature_base_string, private_key_or_secret
      self
    end

    def verify!(public_key_or_secret)
      if alg.to_s == 'none'
        raise UnexpectedAlgorithm if public_key_or_secret
        signature == '' or raise VerificationFailed
      else
        public_key_or_secret && valid?(public_key_or_secret) or
        raise VerificationFailed
      end
    end

    def update(hash_or_jwt)
      super
      if hash_or_jwt.is_a? JSON::JWT
        self.header = hash_or_jwt.header
        self.signature = hash_or_jwt.signature
      end
      self
    end

    private

    def digest
      OpenSSL::Digest.new "SHA#{algorithm.to_s[2, 3]}"
    end

    def hmac?
      ['HS256', 'HS384', 'HS512'].include? algorithm.to_s
    end

    def rsa?
      ['RS256', 'RS384', 'RS512'].include? algorithm.to_s
    end

    def ecdsa?
      ['ES256', 'ES384', 'ES512'].include? algorithm.to_s
    end

    def signature_base_string
      @signature_base_string ||= [
        header.to_json,
        self.to_json
      ].collect do |segment|
        UrlSafeBase64.encode64 segment
      end.join('.')
    end

    def sign(signature_base_string, private_key_or_secret)
      private_key_or_secret = with_jwk_support private_key_or_secret
      case
      when hmac?
        secret = private_key_or_secret
        OpenSSL::HMAC.digest digest, secret, signature_base_string
      when rsa?
        private_key = private_key_or_secret
        private_key.sign digest, signature_base_string
      when ecdsa?
        private_key = private_key_or_secret
        verify_ecdsa_group! private_key
        asn1_to_raw(
          private_key.dsa_sign_asn1(digest.digest signature_base_string),
          private_key
        )
      else
        raise UnexpectedAlgorithm.new('Unknown Signature Algorithm')
      end
    end

    def valid?(public_key_or_secret)
      public_key_or_secret = with_jwk_support public_key_or_secret
      case
      when hmac?
        secure_compare sign(signature_base_string, public_key_or_secret), signature
      when rsa?
        public_key = public_key_or_secret
        public_key.verify digest, signature, signature_base_string
      when ecdsa?
        public_key = public_key_or_secret
        verify_ecdsa_group! public_key
        public_key.dsa_verify_asn1(
          digest.digest(signature_base_string),
          raw_to_asn1(signature, public_key)
        )
      else
        raise UnexpectedAlgorithm.new('Unknown Signature Algorithm')
      end
    rescue TypeError => e
      raise UnexpectedAlgorithm.new(e.message)
    end

    def verify_ecdsa_group!(key)
      group_name = case digest.digest_length * 8
      when 256
        :prime256v1
      when 384
        :secp384r1
      when 512
        :secp521r1
      end
      key.group = OpenSSL::PKey::EC::Group.new group_name.to_s
      key.check_key
    end

    def raw_to_asn1(signature, public_key)
      byte_size = (public_key.group.degree + 7) / 8
      r = signature[0..(byte_size - 1)]
      s = signature[byte_size..-1]
      OpenSSL::ASN1::Sequence.new([r, s].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
    end

    def asn1_to_raw(signature, private_key)
      byte_size = (private_key.group.degree + 7) / 8
      OpenSSL::ASN1.decode(signature).value.map { |value| value.value.to_s(2).rjust(byte_size, "\x00") }.join
    end

    class << self
      def decode_compact_serialized(input, public_key_or_secret)
        unless input.count('.') + 1 == NUM_OF_SEGMENTS
          raise InvalidFormat.new("Invalid JWS Format. JWS should include #{NUM_OF_SEGMENTS} segments.")
        end
        header, claims, signature = input.split('.', JWS::NUM_OF_SEGMENTS).collect do |segment|
          UrlSafeBase64.decode64 segment.to_s
        end
        header, claims = [header, claims].collect do |json|
          Hashery::KeyHash[MultiJson.load(json)]
        end
        jws = new claims
        jws.header = header
        jws.signature = signature
        jws.signature_base_string = input.split('.')[0, JWS::NUM_OF_SEGMENTS - 1].join('.')
        jws.verify! public_key_or_secret unless public_key_or_secret == :skip_verification
        jws
      end

      def decode_json_serialized(input, public_key_or_secret)
        input = Hashery::KeyHash[input]
        header, payload, signature = if input[:signatures] && !input[:signatures].empty?
          [
            input[:signatures].first[:protected],
            input[:payload],
            input[:signatures].first[:signature]
          ].collect do |segment|
            segment
          end
        else
          [:protected, :payload, :signature].collect do |key|
            input[key]
          end
        end
        compact_serialized = [header, payload, signature].join('.')
        decode_compact_serialized compact_serialized, public_key_or_secret
      end
    end
  end
end
