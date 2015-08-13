require 'spec_helper'

describe JSON::JWK do
  describe '#initialize' do
    subject { JSON::JWK.new key }

    context 'with OpenSSL::PKey::RSA' do
      let(:key) { public_key }
      it { should be_instance_of JSON::JWK }
    end

    context 'with OpenSSL::PKey::EC' do
      let(:key) { public_key :ecdsa }
      it { should be_instance_of JSON::JWK }
    end

    context 'with String' do
      let(:key) { 'secret' }
      it { should be_instance_of JSON::JWK }
    end

    context 'with JSON::JWK' do
      let(:key) do
        JSON::JWK.new(
          k: 'secret',
          kty: :oct
        )
      end
      it { should be_instance_of JSON::JWK }
    end

    context 'with Hash' do
      let(:key) do
        {
          k: 'secret',
          kty: :oct
        }
      end
      it { should be_instance_of JSON::JWK }
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
    its(:e) { jwk[:e].should == UrlSafeBase64.encode64(public_key.e.to_s(2)) }
    its(:n) { jwk[:n].should == UrlSafeBase64.encode64(public_key.n.to_s(2)) }

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
  end

  context 'when ECDSA public key given' do
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
  end

  describe 'unknown key type' do
    it do
      key = OpenSSL::PKey::DSA.generate 256
      expect do
        JSON::JWK.new key
      end.to raise_error JSON::JWK::UnknownAlgorithm, 'Unknown Key Type'
    end
  end

  describe '#thumbprint' do
    context 'when kty=RSA' do
      subject do
        JSON::JWK.new(
          kty: :RSA,
          e: 'AQAB',
          n: '0OIOijENzP0AXnxP-X8Dnazt3m4NTamfNsSCkH4xzgZAJj2Eur9-zmq9IukwN37lIrm3oAE6lL4ytNkv-DQpAivKLE8bh4c9qlB9o32VWyg-mg-2af-JlfGXYoaCW2GDMOV6EKqHBxE0x1EI0tG4gcNwO6A_kYtK6_ACgTQudWz_gnPrL-QCunjIMbbrK9JqgMZhgMARMQpB-j8oet2FFsEcquR5MWtBeAn7qC1AD2ya0EmzplZJP6oCka_VVuxAnyWfRGA0bzCBRIVbcGUXVNIXpRtA_4960e7AlGfMSA-ofN-vo7v0CMkA8BwpZHai9CAJ-cTCX1AVbov83LVIWw'
        )
      end
      its(:thumbprint) { should == 'fFn3D1P0H7Qo1ugQ-5LM6LC63LtArbkPsbQcs2F-1yA' }
    end

    context 'when kty=EC' do
      subject do
        JSON::JWK.new(
          kty: 'EC',
          crv: 'P-256',
          x: 'saPyrO4Lh9kh2FxrF9y1QVmZznWnRRJwpr12UHqzrVY',
          y: 'MMz4W9zzqlrJhqr-JyrpvlnaIIyZQE6DfrgPkxMAw1M'
        )
      end
      its(:thumbprint) { should == '-egRpLjyZCqxBh4OOfd8JSvXwayHmNFAUNkbi8exfhc' }
    end

    context 'when kty=oct' do
      subject do
        JSON::JWK.new(
          kty: 'oct',
          k: 'secret'
        )
      end
      its(:thumbprint) { should == 'XZPWsTEZFIerowAF9GHzBtq5CkAOcVvIBnkMu0IIQH0' }
    end
  end

  describe '.decode' do
    context 'when RSA' do
      subject do
        JSON::JWK.decode(
          kty: :RSA,
          n: n,
          e: e
        )
      end
      let(:e) { 'AQAB' }
      let(:n) { 'AK8ppaAGn6N3jDic2DhDN5mI5mWzvhfL1AFZOS9q2EBM8L5sjZbYiaHeNoKillZGmEF9a9g6Z20bDnoHTuHPsx93HYkZqPumFZ8K9lLCbqKAMWw2Qgk10RgrZ-kblJotTBCeer9-tZSWO-OWFzP4gp8MpSuQOQbwTJwDgEkFIQLUK2YgzWbn1PoW8xcfbVyWhZD880ELGRW6GhRgYAl0DN_EQS8kyUa0CusYCzOOg2W3-7qjYeojyP6jiOEr-eyjC7hcUvTVoTfz84BiZv72KS3i5JS8ZNNuRp5Ce51wjoDDUoNxDLWv6Da6qMaGpKz6NTSNbvhE_KFhpp4wf5yRQD8=' }
      let(:pem) do
        <<-PEM.strip_heredoc
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArymloAafo3eMOJzYOEM3
          mYjmZbO+F8vUAVk5L2rYQEzwvmyNltiJod42gqKWVkaYQX1r2DpnbRsOegdO4c+z
          H3cdiRmo+6YVnwr2UsJuooAxbDZCCTXRGCtn6RuUmi1MEJ56v361lJY745YXM/iC
          nwylK5A5BvBMnAOASQUhAtQrZiDNZufU+hbzFx9tXJaFkPzzQQsZFboaFGBgCXQM
          38RBLyTJRrQK6xgLM46DZbf7uqNh6iPI/qOI4Sv57KMLuFxS9NWhN/PzgGJm/vYp
          LeLklLxk025GnkJ7nXCOgMNSg3EMta/oNrqoxoakrPo1NI1u+ET8oWGmnjB/nJFA
          PwIDAQAB
          -----END PUBLIC KEY-----
        PEM
      end

      it { should be_instance_of OpenSSL::PKey::RSA }
      its(:to_pem) { should == pem }

      it 'should support string keys' do
        JSON::JWK.decode(
          'kty' => 'RSA',
          'n' => n,
          'e' => e
        ).should be_instance_of OpenSSL::PKey::RSA
      end
    end

    context 'when ECDSA' do
      [{
        alg: 'EC',
        crv: 'P-256',
        kty: 'EC',
        x: 'saPyrO4Lh9kh2FxrF9y1QVmZznWnRRJwpr12UHqzrVY',
        y: 'MMz4W9zzqlrJhqr-JyrpvlnaIIyZQE6DfrgPkxMAw1M'
      }, {
        alg: 'EC',
        crv: 'P-384',
        kty: 'EC',
        x: 'plzApyFnK7qzhg5XnIZbFj2hZoH2Vdl4-RFm7DnsNMG9tyqrpfq2RyjfKABbcFRt',
        y: 'ixBzffhk3fcbmeipGLkvQBNCzeNm6QL3hOUTH6IFBzOL0Y7HsGTopNTTspLjlivb'
      }, {
        alg: 'EC',
        crv: 'P-521',
        kty: 'EC',
        x: 'AcMCD-a0a6rnE9TvC0mOqF_DGXRg5Y3iTb4eHNwTm2kD6iujx9M_f8d_FGHr0OhpqzEn4rYPYZouGsbIPEgL0q__',
        y: 'AULYEd8l-bV_BI289aezhSLZ1RDF2ltgDPEy9Y7YtqYa4cJcpiyzVDMpXWwBp6cjg6TXINkoVrVXZhN404ihu4I2'
      }].each do |jwk|
        describe jwk['crv'] do
          it do
            JSON::JWK.decode(jwk).should be_instance_of OpenSSL::PKey::EC
          end
        end
      end
    end

    context 'when invalid algorithm' do
      it do
        expect do
          JSON::JWK.decode(
            kty: :XXX
          )
        end.to raise_error JSON::JWK::UnknownAlgorithm
      end
    end

    context 'when no algorithm' do
      it do
        expect do
          JSON::JWK.decode(
            x: :x
          )
        end.to raise_error JSON::JWK::UnknownAlgorithm
      end
    end
  end
end
