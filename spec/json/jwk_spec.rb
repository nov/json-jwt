require 'spec_helper'

describe JSON::JWK do
  let(:rsa_public_key) { public_key }

  context 'when RSA public key given' do
    let(:jwk) { JSON::JWK.new rsa_public_key }
    it { jwk.should include :alg, :exp, :mod }
    its(:alg) { jwk[:alg].should == :RSA }
    its(:exp) { jwk[:exp].should == UrlSafeBase64.encode64(rsa_public_key.e.to_s(2)) }
    its(:mod) { jwk[:mod].should == UrlSafeBase64.encode64(rsa_public_key.n.to_s(2)) }

    context 'when kid/use options given' do
      let(:jwk) { JSON::JWK.new rsa_public_key, :kid => '12345', :use => :sig }
      it { jwk.should include :kid, :use }
      its(:kid) { jwk[:kid].should == '12345' }
      its(:use) { jwk[:use].should == :sig }
    end
  end
end