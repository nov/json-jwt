require 'spec_helper'

describe JSON::JWT do
  let(:jwt) { JSON::JWT.new claims }
  let(:jws) do
    jwt.header[:alg] = :HS256
    jws = JSON::JWS.new jwt
    jws.signature = 'signature'
    jws
  end
  let(:claims) do
    {
      iss: 'joe',
      exp: 1300819380,
      :'http://example.com/is_root' => true
    }
  end
  let(:no_signed) do
    'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
  end

  context 'when not signed nor encrypted' do
    it do
      jwt.to_s.should == no_signed
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
        header, claims, signature = no_signed.split('.', 3).collect do |segment|
          UrlSafeBase64.decode64 segment.to_s
        end
        header, claims = [header, claims].collect do |json|
          JSON.parse json, symbolize_names: true, symbolize_keys: true
        end
        jwt = JSON::JWT.new claims
        jwt.header = header
        jwt.signature = signature
        jwt
      end

      context 'when no signature nor public_key_or_secret given' do
        it do
          jwt.verify.should be_true
        end
      end

      context 'when public_key_or_secret given' do
        it do
          expect do
            jwt.verify 'secret'
          end.to raise_error JSON::JWT::UnexpectedAlgorithm
        end
      end

      context 'when signature given' do
        before { jwt.signature = 'signature' }

        it do
          expect do
            jwt.verify
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
  end
end
