require 'spec_helper'

describe JSON::JWK do
  describe '#initialize' do
    let(:jwk) { JSON::JWK.new key }
    subject { jwk }

    shared_examples_for :jwk_with_kid do
      it { should be_instance_of JSON::JWK }
      describe 'kid' do
        subject { jwk[:kid] }
        it { should == jwk.thumbprint }
      end
    end

    shared_examples_for :jwk_without_kid do
      it { should be_instance_of JSON::JWK }
      describe 'kid' do
        subject { jwk[:kid] }
        it { should be_blank }
      end
    end

    context 'when no imput' do
      it do
        JSON::JWK.new.should be_blank
      end
    end

    context 'with OpenSSL::PKey::RSA' do
      let(:key) { public_key }
      it_behaves_like :jwk_with_kid
    end

    context 'with OpenSSL::PKey::EC' do
      let(:key) { public_key :ecdsa }
      it_behaves_like :jwk_with_kid
    end

    context 'with String' do
      let(:key) { 'secret' }
      it_behaves_like :jwk_with_kid
    end

    context 'with JSON::JWK' do
      let(:key) do
        JSON::JWK.new(
          k: 'secret',
          kty: :oct
        )
      end
      it_behaves_like :jwk_with_kid
    end

    context 'with Hash' do
      let(:key) do
        {
          k: 'secret',
          kty: :oct
        }
      end
      it_behaves_like :jwk_with_kid
    end

    context 'with nothing' do
      let(:jwk) { JSON::JWK.new }
      it_behaves_like :jwk_without_kid
    end
  end

  describe '#content_type' do
    let(:jwk) { JSON::JWK.new public_key }
    it do
      jwk.content_type.should == 'application/jwk+json'
    end
  end

  context 'when RSA public key given' do
    let(:jwk) { JSON::JWK.new public_key }
    it { jwk.keys.collect(&:to_sym).should include :kty, :e, :n }
    its(:kty) { jwk[:kty].should == :RSA }
    its(:e) { jwk[:e].should == Base64.urlsafe_encode64(public_key.e.to_s(2), padding: false) }
    its(:n) { jwk[:n].should == Base64.urlsafe_encode64(public_key.n.to_s(2), padding: false) }

    context 'when kid/use options given' do
      let(:jwk) { JSON::JWK.new public_key, kid: '12345', use: :sig }
      it { jwk.keys.collect(&:to_sym).should include :kid, :use }
      its(:kid) { jwk[:kid].should == '12345' }
      its(:use) { jwk[:use].should == :sig }
    end

    describe '#thumbprint' do
      context 'using default hash function' do
        subject { jwk.thumbprint }
        it { should == 'nuBTimkcSt_AuEsD8Yv3l8CoGV31bu_3gsRDGN1iVKA' }
      end

      context 'using SHA512 hash function' do
        subject { jwk.thumbprint :SHA512 }
        it { should == '6v7pXTnQLMiQgvJlPJUdhAUSuGLzgF8C1r3ABAMFet6bc53ea-Pq4ZGbGu3RoAFsNRT1-RhTzDqtqXuLU6NOtw' }
      end
    end

    describe '#to_key' do
      it { jwk.to_key.should be_instance_of OpenSSL::PKey::RSA }
    end
  end

  context 'when EC public key given' do
    let(:jwk) { JSON::JWK.new public_key(:ecdsa) }
    let(:expected_coordinates) do
      {
        256 => {
          x: 'saPyrO4Lh9kh2FxrF9y1QVmZznWnRRJwpr12UHqzrVY',
          y: 'MMz4W9zzqlrJhqr-JyrpvlnaIIyZQE6DfrgPkxMAw1M'
        },
        384 => {
          x: 'plzApyFnK7qzhg5XnIZbFj2hZoH2Vdl4-RFm7DnsNMG9tyqrpfq2RyjfKABbcFRt',
          y: 'ixBzffhk3fcbmeipGLkvQBNCzeNm6QL3hOUTH6IFBzOL0Y7HsGTopNTTspLjlivb'
        },
        512 => {
          x: 'AcMCD-a0a6rnE9TvC0mOqF_DGXRg5Y3iTb4eHNwTm2kD6iujx9M_f8d_FGHr0OhpqzEn4rYPYZouGsbIPEgL0q__',
          y: 'AULYEd8l-bV_BI289aezhSLZ1RDF2ltgDPEy9Y7YtqYa4cJcpiyzVDMpXWwBp6cjg6TXINkoVrVXZhN404ihu4I2'
        }
      }
    end

    [256, 384, 512].each do |digest_length|
      describe "EC#{digest_length}" do
        let(:jwk) { JSON::JWK.new public_key(:ecdsa, digest_length: digest_length) }
        it { jwk.keys.collect(&:to_sym).should include :kty, :crv, :x, :y }
        its(:kty) { jwk[:kty].should == :EC }
        its(:x) { jwk[:x].should == expected_coordinates[digest_length][:x] }
        its(:y) { jwk[:y].should == expected_coordinates[digest_length][:y] }
      end
    end

    describe 'unknown curve' do
      it do
        key = OpenSSL::PKey::EC.new('secp112r2').generate_key
        expect do
          JSON::JWK.new key
        end.to raise_error JSON::JWK::UnknownAlgorithm, 'Unknown EC Curve'
      end
    end

    describe '#thumbprint' do
      context 'using default hash function' do
        subject { jwk.thumbprint }
        it { should == '-egRpLjyZCqxBh4OOfd8JSvXwayHmNFAUNkbi8exfhc' }
      end

      context 'using SHA512 hash function' do
        subject { jwk.thumbprint :SHA512 }
        it { should == 'B_yXDZJ9doudaVCj5q5vqxshvVtW2IFnz_ypvRt5O60gemkDAhO78L6YMyTWH0ZRm15cO2_laTSaNO9yZQFsvQ' }
      end
    end

    describe '#to_key' do
      it { jwk.to_key.should be_instance_of OpenSSL::PKey::EC }
    end
  end

  context 'when shared secret given' do
    let(:jwk) { JSON::JWK.new 'secret' }
    its(:kty) { jwk[:kty].should == :oct }
    its(:x) { jwk[:k].should == 'secret' }

    describe '#thumbprint' do
      context 'using default hash function' do
        subject { jwk.thumbprint }
        it { should == 'XZPWsTEZFIerowAF9GHzBtq5CkAOcVvIBnkMu0IIQH0' }
      end

      context 'using SHA512 hash function' do
        subject { jwk.thumbprint :SHA512 }
        it { should == 'rK7EtcEe9Xr0kryR9lNnyOTRe7Vb_BglbTBtbcVG2LzvL26_PFaMCwOtiUiXWfCK-wV8vcxjmvbcvV4ZxDE0FQ' }
      end
    end

    describe '#to_key' do
      it { jwk.to_key.should be_instance_of String }
    end
  end

  describe 'unknown key type' do
    it do
      key = OpenSSL::PKey::DSA.generate 256
      expect do
        JSON::JWK.new key
      end.to raise_error JSON::JWK::UnknownAlgorithm, 'Unknown Key Type'
    end
  end
end
