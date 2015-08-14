require 'spec_helper'

describe JSON::JWK::JWKizable do
  describe '#to_jwk' do
    subject { key.to_jwk }

    shared_examples_for :jwkizable_as_public do
      it { should be_instance_of JSON::JWK }
      it { should include *public_key_attributes.collect(&:to_s) }
      it { should_not include *private_key_attributes.collect(&:to_s) }
    end

    shared_examples_for :jwkizable_as_private do
      it { should be_instance_of JSON::JWK }
      it { should include *public_key_attributes.collect(&:to_s) }
      it { should include *private_key_attributes.collect(&:to_s) }
    end

    describe OpenSSL::PKey::RSA do
      let(:public_key_attributes) { [:kty, :n, :e] }
      let(:private_key_attributes) { [:d, :p, :q] }

      describe :public_key do
        let(:key) { public_key :rsa }
        it_behaves_like :jwkizable_as_public
      end

      describe :private_key do
        let(:key) { private_key :rsa }
        it_behaves_like :jwkizable_as_private
      end
    end

    describe OpenSSL::PKey::EC do
      let(:public_key_attributes) { [:kty, :crv, :x, :y] }
      let(:private_key_attributes) { [:d] }

      describe :public_key do
        let(:key) { public_key :ecdsa }
        it_behaves_like :jwkizable_as_public
      end

      describe :private_key do
        let(:key) { private_key :ecdsa }
        it_behaves_like :jwkizable_as_private
      end
    end
  end
end