module JSON
  class JWK
    module JWKizable
      module RSA
        def to_jwk(ex_params = {})
          params = {
            kty: :RSA,
            e: UrlSafeBase64.encode64(e.to_s(2)),
            n: UrlSafeBase64.encode64(n.to_s(2))
          }.merge ex_params
          if private?
            params.merge!(
              d: UrlSafeBase64.encode64(d.to_s(2))
            )
          end
          JWK.new params
        end
      end

      module EC
        def to_jwk(ex_params = {})
          if private_key?
            # TODO: how to calculate "d" ?
            raise UnknownAlgorithm.new('EC private key not supported yet.')
          end
          params = {
            kty: :EC,
            crv: curve_name,
            x: UrlSafeBase64.encode64(coodinates[:x].to_s),
            y: UrlSafeBase64.encode64(coodinates[:y].to_s)
          }.merge ex_params
          JWK.new params
        end

        private

        def curve_name
          case group.curve_name
          when 'prime256v1'
            :'P-256'
          when 'secp384r1'
            :'P-384'
          when 'secp521r1'
            :'P-521'
          else
            raise UnknownAlgorithm.new('Unknown EC Curve')
          end
        end

        def coodinates
          unless @coodinates
            hex = public_key.to_bn.to_s(16)
            data_len = hex.length - 2
            type = hex[0, 2]
            hex_x = hex[2, data_len / 2]
            hex_y = hex[2 + data_len / 2, data_len / 2]
            @coodinates = {
              x: [hex_x].pack("H*"),
              y: [hex_y].pack("H*")
            }
          end
          @coodinates
        end
      end
    end
  end
end

OpenSSL::PKey::RSA.include JSON::JWK::JWKizable::RSA
OpenSSL::PKey::EC.include JSON::JWK::JWKizable::EC