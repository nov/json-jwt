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

    context 'when no algirithm specified' do
      subject { jwt.sign(key) }

      context 'when key is String' do
        let(:key) { shared_secret }
        its(:alg) { should == :HS256 }
      end

      context 'when key is RSA key' do
        let(:key) { private_key }
        its(:alg) { should == :RS256 }
      end

      context 'when key is EC key' do
        context 'when prime256v1' do
          let(:key) { private_key(:ecdsa) }
          its(:alg) { should == :ES256 }
        end

        context 'when secp384r1' do
          let(:key) { private_key(:ecdsa, digest_length: 384) }
          its(:alg) { should == :ES384 }
        end

        context 'when secp521r1' do
          let(:key) { private_key(:ecdsa, digest_length: 512) }
          its(:alg) { should == :ES512 }
        end
      end

      context 'when key is JWK with kty=okt' do
        let(:key) { JSON::JWK.new shared_secret }
        its(:alg) { should == :HS256 }
      end

      context 'when key is JWK with kty=RSA' do
        let(:key) { JSON::JWK.new private_key }
        its(:alg) { should == :RS256 }
      end

      context 'when key is JWK with kty=EC' do
        context 'when prime256v1' do
          let(:key) { JSON::JWK.new private_key(:ecdsa) }
          its(:alg) { should == :ES256 }
        end

        context 'when secp384r1' do
          let(:key) { JSON::JWK.new private_key(:ecdsa, digest_length: 384) }
          its(:alg) { should == :ES384 }
        end

        context 'when secp521r1' do
          let(:key) { JSON::JWK.new private_key(:ecdsa, digest_length: 512) }
          its(:alg) { should == :ES512 }
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

    describe 'object copy behaviour' do
      before do
        @jwt = JSON::JWT.new(obj: {foo: :bar})
        @jws = @jwt.sign('secret')
      end

      context 'when original JWT is modified' do
        before do
          @jwt.header[:x] = :x
          @jwt[:obj][:x] = :x
        end

        describe 'copied JWS' do
          it 'should be affected as shallow copy, but not as a simple reference' do
            @jws.header.should_not include :x
            @jws[:obj].should include :x
          end
        end
      end

      context 'when copied JWS is modified' do
        before do
          @jws.header[:x] = :x
          @jws[:obj][:x] = :x
        end

        describe 'original JWT' do
          it 'should be affected as shallow copy, but not as a simple reference' do
            @jwt.header.should_not include :x
            @jwt[:obj].should include :x
          end
        end
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
                Base64.urlsafe_encode64(malformed_header, padding: false),
                payload,
                ''
              ].join('.')
            end

            it do
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
                Base64.urlsafe_encode64(malformed_header, padding: false),
                payload,
                ''
              ].join('.')
            end

            it do
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
                [Base64.urlsafe_encode64(malformed_header, padding: false), payload].join('.')
              )
              [
                Base64.urlsafe_encode64(malformed_header, padding: false),
                payload,
                Base64.urlsafe_encode64(malformed_signature, padding: false)
              ].join('.')
            end

            it do
              expect do
                JSON::JWT.decode malformed_jwt_string, public_key
              end.to raise_error JSON::JWS::UnexpectedAlgorithm
            end
          end
        end

        context 'from alg=PS512' do
          let(:jws) do
            jwt.sign private_key, :PS512
          end

          if pss_supported?
            context 'to alg=PS256' do
              let(:malformed_jwt_string) do
                header, payload, signature = jws.to_s.split('.')
                malformed_header = {alg: :PS256}.to_json
                digest = OpenSSL::Digest.new('SHA256')
                malformed_signature = private_key.sign_pss(
                  digest,
                  [Base64.urlsafe_encode64(malformed_header, padding: false), payload].join('.'),
                  salt_length: :digest,
                  mgf1_hash: digest
                )
                [
                  Base64.urlsafe_encode64(malformed_header, padding: false),
                  payload,
                  Base64.urlsafe_encode64(malformed_signature, padding: false)
                ].join('.')
              end

              context 'when verification algorithm is specified' do
                it do
                  expect do
                    JSON::JWT.decode malformed_jwt_string, public_key, :PS512
                  end.to raise_error JSON::JWS::UnexpectedAlgorithm, 'Unexpected alg header'
                end
              end

              context 'otherwise' do
                it do
                  expect do
                    JSON::JWT.decode malformed_jwt_string, public_key
                  end.not_to raise_error
                end
              end
            end

            context 'to alg=RS516' do
              let(:malformed_jwt_string) do
                header, payload, signature = jws.to_s.split('.')
                malformed_header = {alg: :RS512}.to_json
                malformed_signature = private_key.sign(
                  OpenSSL::Digest.new('SHA512'),
                  [Base64.urlsafe_encode64(malformed_header, padding: false), payload].join('.')
                )
                [
                  Base64.urlsafe_encode64(malformed_header, padding: false),
                  payload,
                  Base64.urlsafe_encode64(malformed_signature, padding: false)
                ].join('.')
              end

              context 'when verification algorithm is specified' do
                it do
                  expect do
                    JSON::JWT.decode malformed_jwt_string, public_key, :PS512
                  end.to raise_error JSON::JWS::UnexpectedAlgorithm, 'Unexpected alg header'
                end
              end

              context 'otherwise' do
                it do
                  expect do
                    JSON::JWT.decode malformed_jwt_string, public_key
                  end.not_to raise_error
                end
              end
            end
          else
            skip 'RSA PSS not supported'
            it do
              expect { jws }.to raise_error 'PS512 isn\'t supported. OpenSSL gem v2.1.0+ is required to use PS512.'
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
              payload: Base64.urlsafe_encode64(claims.to_json, padding: false),
              signatures: [{
                protected: Base64.urlsafe_encode64(signed.header.to_json, padding: false),
                signature: Base64.urlsafe_encode64(signed.signature, padding: false)
              }]
            }
          end
          it_behaves_like :json_serialization_parser
        end

        context 'when flattened' do
          let(:serialized) do
            {
              protected: Base64.urlsafe_encode64(signed.header.to_json, padding: false),
              payload: Base64.urlsafe_encode64(claims.to_json, padding: false),
              signature: Base64.urlsafe_encode64(signed.signature, padding: false)
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

      context 'when alg & enc is specified' do
        context 'when expected' do
          it do
            expect do
              JSON::JWT.decode(input, private_key, 'RSA1_5', 'A128CBC-HS256')
            end.not_to raise_error
          end
        end

        context 'when alg is unexpected' do
          it do
            expect do
              JSON::JWT.decode(input, private_key, 'dir', 'A128CBC-HS256')
            end.to raise_error JSON::JWE::UnexpectedAlgorithm, 'Unexpected alg header'
          end
        end

        context 'when enc is unexpected' do
          it do
            expect do
              JSON::JWT.decode(input, private_key, 'RSA1_5', 'A128GCM')
            end.to raise_error JSON::JWE::UnexpectedAlgorithm, 'Unexpected enc header'
          end
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
            JSON::JWT.decode 'header.payload.signature.too.many.dots'
          end.to raise_error JSON::JWT::InvalidFormat
        end
      end
    end
  end

  describe '.pretty_generate' do
    subject { JSON::JWT.pretty_generate jws.to_s }
    its(:size) { should == 2 }
    its(:first) do
      should == <<~HEADER.chop
        {
          "typ": "JWT",
          "alg": "HS256"
        }
      HEADER
    end
    its(:last) do
      should == <<~HEADER.chop
        {
          "iss": "joe",
          "exp": 1300819380,
          "http://example.com/is_root": true
        }
      HEADER
    end
  end
end
