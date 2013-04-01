require 'spec_helper'

describe JSON::JWE do
  let(:plain_text) { 'Hello World' }
  let(:jwe) { JSON::JWE.new plain_text }

  context 'when alg=RSA-OAEP & enc=A256GCM' do
    before do
      jwe.alg, jwe.enc = :'RSA-OAEP', :A256GCM
    end

    # it do
    #   expect do
    #     jwe.encrypt! public_key
    #   end.to raise_error NotImplementedError
    # end
  end
end
