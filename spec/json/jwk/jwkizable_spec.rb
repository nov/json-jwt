require 'spec_helper'

describe JSON::JWK::JWKizable do
  shared_examples_for :jwkizable do
    describe '#to_jwk' do
      it { key.to_jwk.should be_instance_of JSON::JWK }
      it { key.to_jwk.should include *expected_attributes.collect(&:to_s) }
    end
  end

  describe OpenSSL::PKey::RSA do
    describe :public_key do
      let(:key) { public_key :rsa }
      let(:expected_attributes) { [:kty, :n, :e] }
      it_behaves_like :jwkizable
    end

    describe :private_key do
      let(:key) { private_key :rsa }
      let(:expected_attributes) { [:kty, :n, :e, :d] }
      it_behaves_like :jwkizable
    end
  end

  describe OpenSSL::PKey::EC do
    describe :public_key do
      let(:key) { public_key :ecdsa }
      let(:expected_attributes) { [:kty, :crv, :x, :y] }
      it_behaves_like :jwkizable
    end

    describe :private_key do
      let(:key) { private_key :ecdsa }
      let(:expected_attributes) { [:kty, :crv, :x, :y] } # NOTE: handled as public key
      it_behaves_like :jwkizable

      context 'when public key is not contained' do
        before { key.public_key = nil }
        it do
          expect do
            key.to_jwk
          end.to raise_error JSON::JWK::UnknownAlgorithm, 'EC private key is not supported yet'
        end
      end
    end
  end
end