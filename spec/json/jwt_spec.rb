require 'spec_helper'

describe JSON::JWT do
  let(:jwt) { JSON::JWT.new claim }
  let(:claim) do
    {
      :iss => 'joe',
      :exp => 1300819380,
      'http://example.com/is_root' => true
    }
  end

  context 'when no sign no encryption' do
    let :result do
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
    end

    it do
      jwt.to_s.should == result
    end
  end

  describe '.sign' do
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
end