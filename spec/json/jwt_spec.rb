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
  end

  describe '#verify' do
    context 'when not signed nor encrypted' do
      let(:jwt) do
        header_base64, claims_base64, signature = no_signed.split('.', 3).collect do |segment|
          UrlSafeBase64.decode64 segment.to_s
        end
        header, claims = [header_base64, claims_base64].collect do |json|
          MultiJson.load(json).with_indifferent_access
        end
        jwt = JSON::JWT.new claims
        jwt.header = header
        jwt.signature = signature
        jwt
      end
      let(:signature_base_string) { no_signed.split('.', 3)[0,2].join('.') }

      context 'when no signature nor public_key_or_secret given' do
        it do
          jwt.verify(signature_base_string).should be_true
        end
      end

      context 'when public_key_or_secret given' do
        it do
          expect do
            jwt.verify signature_base_string, 'secret'
          end.to raise_error JSON::JWT::UnexpectedAlgorithm
        end
      end

      context 'when signature given' do
        before { jwt.signature = 'signature' }

        it do
          expect do
            jwt.verify signature_base_string
          end.to raise_error JSON::JWT::VerificationFailed
        end
      end
    end

    context 'when signed' do
      it 'should delegate verification to JWS' do
        jws.should_receive(:verify)
        JSON::JWS.should_receive(:new).and_return(jws)
        jwt.verify 'shared_secret'
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

      context 'when :skip_verification given as secret/key' do
        it 'should skip verification' do
          expect do
            jwt = JSON::JWT.decode jws.to_s, :skip_verification
            jwt.header.should == {'alg' => 'HS256', 'typ' => 'JWT'}
          end.not_to raise_error
        end
      end
    end

    context 'when encrypted' do
      let(:input) { jwt.encrypt(public_key).to_s }
      let(:shared_key) { SecureRandom.hex 16 } # default shared key is too short

      it 'should decryptable' do
        JSON::JWT.decode(input, private_key).should be_a JSON::JWE
      end

      context 'when :skip_decryption given as secret/key' do
        it 'should skip verification' do
          expect do
            jwe = JSON::JWT.decode input, :skip_decryption
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
