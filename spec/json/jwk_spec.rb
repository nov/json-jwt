require 'spec_helper'

describe JSON::JWK do
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
  end

  context 'when ECDSA public key given' do
    let(:expected_coodinates) do
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
        its(:x) { jwk[:x].should == expected_coodinates[digest_length][:x] }
        its(:y) { jwk[:y].should == expected_coodinates[digest_length][:y] }
      end
    end

    describe 'unknown curve' do
      it do
        key = OpenSSL::PKey::EC.new('secp112r2').generate_key
        expect do
          JSON::JWK.new key
        end.to raise_error JSON::JWK::UnknownAlgorithm, 'Unknown ECDSA Curve'
      end
    end
  end

  describe 'unknown algorithm' do
    it do
      key = OpenSSL::PKey::DSA.generate 256
      expect do
        JSON::JWK.new key
      end.to raise_error JSON::JWK::UnknownAlgorithm, 'Unknown Algorithm'
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
        if RUBY_VERSION >= '1.9.3'
          <<-PEM
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
        else
          <<-PEM
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArymloAafo3eMOJzYOEM3mYjmZbO+F8vUAVk5L2rYQEzwvmyNltiJ
od42gqKWVkaYQX1r2DpnbRsOegdO4c+zH3cdiRmo+6YVnwr2UsJuooAxbDZCCTXR
GCtn6RuUmi1MEJ56v361lJY745YXM/iCnwylK5A5BvBMnAOASQUhAtQrZiDNZufU
+hbzFx9tXJaFkPzzQQsZFboaFGBgCXQM38RBLyTJRrQK6xgLM46DZbf7uqNh6iPI
/qOI4Sv57KMLuFxS9NWhN/PzgGJm/vYpLeLklLxk025GnkJ7nXCOgMNSg3EMta/o
NrqoxoakrPo1NI1u+ET8oWGmnjB/nJFAPwIDAQAB
-----END RSA PUBLIC KEY-----
          PEM
        end
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
      if RUBY_VERSION >= '2.0.0'
        [{
          alg: 'EC',
          crv: 'P-256',
          kty: 'EC',
          x: 'eZXWiRe0I3TvHPXiGnvO944gjF1o4UmitH2CVwYIrPg',
          y: 'AKFNss7S35tOsp5iY7-YuLGs2cLrTKFk80JvgVzMPHQ3'
        }, {
          alg: 'EC',
          crv: 'P-384',
          kty: 'EC',
          x: 'XGp9ovRmtaBjlZKGI1XDBUB6F3d4Xov4JFKUCaeVjMD0_GAp20IB_wZz6howe3yi',
          y: 'Vhy6zh3KOkDqSA5WP6BtDyS9CZR7RoCCWfwymBB3HIBIR_yl32hnSYXtlwEr2EoK'
        }, {
          alg: 'EC',
          crv: 'P-521',
          kty: 'EC',
          x: 'KrVaPTvvYmUUSf_1UpwJt_Lg9UT-8OHD_AUd-d7-Q8Rfs4t-lTJ5KEyjbfMzTHsvNulWftuaMH6Ap3l5vbDb2nQ',
          y: 'AIxSEGvlKlWZiN_Rc3VjBs5oVB5l-JfCZHm2LyZpOxAzWrpjHlK121H2ZngM8Ra8ggKa64hEMDE1fMV__C_EZv9m'
        }].each do |jwk|
          describe jwk['crv'] do
            it do
              JSON::JWK.decode(jwk).should be_instance_of OpenSSL::PKey::EC
            end
          end
        end
      else
        it do
          expect do
            JSON::JWK.decode(
              kty: :EC,
              crv: 'P-256',
              x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
              y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM'
            )
          end.to raise_error JSON::JWK::UnknownAlgorithm
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
