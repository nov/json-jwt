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
              d: UrlSafeBase64.encode64(d.to_s(2)),
              p: UrlSafeBase64.encode64(p.to_s(2)),
              q: UrlSafeBase64.encode64(q.to_s(2))
            )
          end
          JWK.new params
        end
      end

      module EC
        def to_jwk(ex_params = {})
          # NOTE:
          #  OpenSSL::PKey::EC instance can be both public & private key at the same time.
          #  In such case, is it handled as public key or private key?
          #  For now, this gem handles any OpenSSL::PKey::EC instances as public key.
          unless public_key?
            raise UnknownAlgorithm.new('EC private key is not supported yet')
          end
          params = {
            kty: :EC,
            crv: curve_name,
            x: UrlSafeBase64.encode64(coordinates[:x].to_s(2)),
            y: UrlSafeBase64.encode64(coordinates[:y].to_s(2))
          }.merge ex_params
          params[:d] = UrlSafeBase64.encode64(coordinates[:d].to_s(2)) if private_key?
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

        def coordinates
          unless @coordinates
            hex = public_key.to_bn.to_s(16)
            data_len = hex.length - 2
            hex_x = hex[2, data_len / 2]
            hex_y = hex[2 + data_len / 2, data_len / 2]
            @coordinates = {
              x: OpenSSL::BN.new([hex_x].pack('H*'), 2),
              y: OpenSSL::BN.new([hex_y].pack('H*'), 2)
            }
            @coordinates[:d] = private_key if private_key?
          end
          @coordinates
        end
      end
    end
  end
end

OpenSSL::PKey::RSA.send :include, JSON::JWK::JWKizable::RSA
OpenSSL::PKey::EC.send :include, JSON::JWK::JWKizable::EC