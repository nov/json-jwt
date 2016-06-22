require 'spec_helper'

describe JSON::JWT do
  let(:jwt) { JSON::JWT.new claims }
  let(:jws) do
    jwt.alg = :HS256
    jws = JSON::JWS.new jwt
    jws.signature = 'signature'
    jws
  end
  let(:claims) do
    {
      iss: 'joe',
      exp: 1300819380,
      'http://example.com/is_root' => true
    }.with_indifferent_access
  end
  let(:no_signed) do
    'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
  end

  context 'when not signed nor encrypted' do
    it do
      jwt.to_s.should == no_signed
    end
  end

  describe '#content_type' do
    it do
      jwt.content_type.should == 'application/jwt'
    end
  end

  describe '#sign' do
    [:HS256, :HS384, :HS512].each do |algorithm|
      context algorithm do
        it do
          jwt.sign(shared_secret, algorithm).should be_a JSON::JWS
        end
      end
    end

    [:RS256, :RS384, :RS512].each do |algorithm|
      context algorithm do
        it do
          jwt.sign(private_key, algorithm).should be_a JSON::JWS
        end
      end
    end

    context 'when non-JWK key is given' do
      let(:key) { private_key }
      it 'should not set kid header automatically' do
        jws = jwt.sign(key, :RS256)
        jws.kid.should be_blank
      end
    end

    context 'when JWK is given' do
      let(:key) { JSON::JWK.new private_key }
      it 'should set kid header automatically' do
        jws = jwt.sign(key, :RS256)
        jwt.kid.should be_blank
        jws.kid.should == key[:kid]
      end
    end
  end

  describe '#encrypt' do
    let(:shared_key) { SecureRandom.hex 16 } # default shared key is too short

    it 'should encryptable without signing' do
      jwt.encrypt(public_key).should be_a JSON::JWE
    end

    it 'should encryptable after signed' do
      jwt.sign(shared_key).encrypt(public_key).should be_a JSON::JWE
    end

    it 'should accept optional algorithm' do
      jwt.encrypt(shared_key, :dir).should be_a JSON::JWE
    end

    it 'should accept optional algorithm and encryption method' do
      jwt.encrypt(SecureRandom.hex(32), :dir, :'A256CBC-HS512').should be_a JSON::JWE
    end

    context 'when non-JWK key is given' do
      let(:key) { shared_key }
      it 'should not set kid header automatically' do
        jwe = jwt.encrypt(key, :dir)
        jwe.kid.should be_blank
      end
    end

    context 'when JWK is given' do
      let(:key) { JSON::JWK.new shared_key }
      it 'should set kid header automatically' do
        jwe = jwt.encrypt(key, :dir)
        jwt.kid.should be_blank
        jwe.kid.should == key[:kid]
      end
    end
  end

  describe '.decode' do
    context 'when not signed nor encrypted' do
      context 'no signature given' do
        it do
          JSON::JWT.decode(no_signed).should == jwt
        end
      end
    end

    context 'when signed' do
      context 'when no secret/key given' do
        it 'should do verification' do
          expect do
            JSON::JWT.decode jws.to_s
          end.to raise_error JSON::JWT::VerificationFailed
        end
      end

      context 'when secret/key given' do
        it 'should do verification' do
          expect do
            JSON::JWT.decode jws.to_s, 'secret'
          end.to raise_error JSON::JWT::VerificationFailed
        end
      end

      context 'when alg header malformed' do
        context 'from alg=HS256' do
          context 'to alg=none' do
            let(:malformed_jwt_string) do
              header, payload, signature = jws.to_s.split('.')
              malformed_header = {alg: :none}.to_json
              [
                UrlSafeBase64.encode64(malformed_header),
                payload,
                ''
              ].join('.')
            end

            it 'should do verification' do
              expect do
                JSON::JWT.decode malformed_jwt_string, 'secret'
              end.to raise_error JSON::JWT::VerificationFailed
            end
          end
        end

        context 'from alg=RS256' do
          let(:jws) do
            jwt.sign private_key, :RS256
          end

          context 'to alg=none' do
            let(:malformed_jwt_string) do
              header, payload, signature = jws.to_s.split('.')
              malformed_header = {alg: :none}.to_json
              [
                UrlSafeBase64.encode64(malformed_header),
                payload,
                ''
              ].join('.')
            end

            it 'should fail verification' do
              expect do
                JSON::JWT.decode malformed_jwt_string, public_key
              end.to raise_error JSON::JWT::UnexpectedAlgorithm
            end
          end

          context 'to alg=HS256' do
            let(:malformed_jwt_string) do
              header, payload, signature = jws.to_s.split('.')
              malformed_header = {alg: :HS256}.to_json
              malformed_signature = OpenSSL::HMAC.digest(
                OpenSSL::Digest.new('SHA256'),
                public_key.to_s,
                [malformed_header, payload].join('.')
              )
              [
                UrlSafeBase64.encode64(malformed_header),
                payload,
                UrlSafeBase64.encode64(malformed_signature)
              ].join('.')
            end

            it 'should fail verification' do
              expect do
                JSON::JWT.decode malformed_jwt_string, public_key
              end.to raise_error JSON::JWS::UnexpectedAlgorithm
            end
          end
        end
      end

      context 'when :skip_verification given as secret/key' do
        it 'should skip verification' do
          expect do
            jwt = JSON::JWT.decode jws.to_s, :skip_verification
            jwt.header.should == {'alg' => 'HS256', 'typ' => 'JWT'}
          end.not_to raise_error
        end
      end

      context 'when JSON Serialization given' do
        let(:signed) { JSON::JWT.new(claims).sign('secret') }

        shared_examples_for :json_serialization_parser do
          context 'when proper secret given' do
            it { JSON::JWT.decode(serialized, 'secret').should == signed }
          end

          context 'when verification skipped' do
            it { JSON::JWT.decode(serialized, :skip_verification).should == signed }
          end

          context 'when wrong secret given' do
            it do
              expect do
                JSON::JWT.decode serialized, 'wrong'
              end.to raise_error JSON::JWT::VerificationFailed
            end
          end
        end

        context 'when general' do
          let(:serialized) do
            {
              payload: UrlSafeBase64.encode64(claims.to_json),
              signatures: [{
                protected: UrlSafeBase64.encode64(signed.header.to_json),
                signature: UrlSafeBase64.encode64(signed.signature)
              }]
            }
          end
          it_behaves_like :json_serialization_parser
        end

        context 'when flattened' do
          let(:serialized) do
            {
              protected: UrlSafeBase64.encode64(signed.header.to_json),
              payload: UrlSafeBase64.encode64(claims.to_json),
              signature: UrlSafeBase64.encode64(signed.signature)
            }
          end
          it_behaves_like :json_serialization_parser
        end
      end
    end

    context 'when encrypted' do
      let(:input) { jwt.encrypt(public_key).to_s }
      let(:shared_key) { SecureRandom.hex 16 } # default shared key is too short

      it 'should decryptable' do
        JSON::JWT.decode(input, private_key).should be_instance_of JSON::JWE
      end

      context 'when :skip_decryption given as secret/key' do
        it 'should skip verification' do
          expect do
            jwe = JSON::JWT.decode input, :skip_decryption
            jwe.should be_instance_of JSON::JWE
            jwe.header.should == {'alg' => 'RSA1_5', 'enc' => 'A128CBC-HS256'}
          end.not_to raise_error
        end
      end
    end

    context 'when JSON parse failed' do
      it do
        expect do
          JSON::JWT.decode('header.payload.signature')
        end.to raise_error JSON::JWT::InvalidFormat
      end
    end

    context 'when unexpected format' do
      context 'when too few dots' do
        it do
          expect do
            JSON::JWT.decode 'header'
          end.to raise_error JSON::JWT::InvalidFormat
        end
      end

      context 'when too many dots' do
        it do
          expect do
            JSON::JWT.decode 'header.payload.signature.something.wrong'
          end.to raise_error JSON::JWT::InvalidFormat
        end
      end
    end
  end
end
