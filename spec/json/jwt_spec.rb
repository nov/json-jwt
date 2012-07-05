require 'spec_helper'

describe JSON::JWT do
  let(:jwt) { JSON::JWT.new claims }
  let(:claims) do
    {
      :iss => 'joe',
      :exp => 1300819380,
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
      context 'when no signature nor public_key_or_secret given' do
        it do
          jwt.verify(no_signed).should be_true
        end
      end

      context 'when public_key_or_secret given' do
        it do
          expect do
            jwt.verify(no_signed, '', 'secret')
          end.should raise_error JSON::JWT::UnexpectedAlgorighm
        end
      end

      context 'when signature given' do
        it do
          expect do
            jwt.verify(no_signed, 'signature')
          end.should raise_error JSON::JWT::VerificationFailed
        end
      end
    end

    context 'when signed' do
      before { jwt.header[:alg] = :HS256 }
      it 'should delegate verification to JWS' do
        jws = JSON::JWS.new jwt
        jws.should_receive(:verify)
        JSON::JWS.should_receive(:new).and_return(jws)
        jwt.verify 'signature_base_string', 'signature', 'shared_secret'
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
  end
end
