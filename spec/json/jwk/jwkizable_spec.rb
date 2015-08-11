require 'spec_helper'

describe JSON::JWK::JWKizable do
  shared_examples_for :public_key_jwkizable do
    subject { public_key alg }
    its(:to_jwk) { should be_instance_of JSON::JWK }
    its(:to_jwk) { should include *public_key_attributes.collect(&:to_s) }
  end

  shared_examples_for :private_key_jwkizable do
    subject { private_key alg }
    its(:to_jwk) { should be_instance_of JSON::JWK }
    its(:to_jwk) { should include *private_key_attributes.collect(&:to_s) }
  end

  shared_examples_for :private_key_not_jwkizable do
    subject { private_key alg }
    it do
      expect do
        subject.to_jwk
      end.to raise_error JSON::JWK::UnknownAlgorithm
    end
  end

  describe OpenSSL::PKey::RSA do
    let(:alg) { :rsa }
    let(:public_key_attributes) { [:kty, :n, :e] }
    let(:private_key_attributes) { [:kty, :n, :e, :d] }
    it_behaves_like :public_key_jwkizable
    it_behaves_like :private_key_jwkizable
  end

  describe OpenSSL::PKey::EC do
    let(:alg) { :ecdsa }
    let(:public_key_attributes) { [:kty, :crv, :x, :y] }
    let(:private_key_attributes) { [:kty, :crv, :x, :y, :d] }
    it_behaves_like :public_key_jwkizable
    it_behaves_like :private_key_not_jwkizable
  end
end