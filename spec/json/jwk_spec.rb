require 'spec_helper'

describe JSON::JWK do
  context 'when RSA public key given' do
    let(:jwk) { JSON::JWK.new public_key }
    it { jwk.should include :alg, :e, :n }
    its(:alg) { jwk[:alg].should == :RSA }
    its(:e) { jwk[:e].should == UrlSafeBase64.encode64(public_key.e.to_s(2)) }
    its(:n) { jwk[:n].should == UrlSafeBase64.encode64(public_key.n.to_s(2)) }

    context 'when kid/use options given' do
      let(:jwk) { JSON::JWK.new public_key, kid: '12345', use: :sig }
      it { jwk.should include :kid, :use }
      its(:kid) { jwk[:kid].should == '12345' }
      its(:use) { jwk[:use].should == :sig }
    end
  end

  context 'when ECDSA public key given' do
    let(:expected_coodinates) do
      {
        256 => {
          x: 'OTUyMUU1NjJFOEQ3NDA0MTRDOEEyQjk5RDQ2NkZERDVFNUYwQzUzMUFGNENBNkMxMTY2Q0NFQzUzQjVGRDMwRg',
          y: 'MDIwQTRENTQwN0ExQkJFNzQwNkJDNjIyMUI5NjUxQTY1NjY5Mjg4QUU1OEE1NjRDNjcwN0Q1RkQ5REM3MDlCNw'
        },
        384 => {
          x: 'QTY1Q0MwQTcyMTY3MkJCQUIzODYwRTU3OUM4NjVCMTYzREExNjY4MUY2NTVEOTc4RjkxMTY2RUMzOUVDMzRDMUJEQjcyQUFCQTVGQUI2NDcyOERGMjgwMDVCNzA1NDZE',
          y: 'OEIxMDczN0RGODY0RERGNzFCOTlFOEE5MThCOTJGNDAxMzQyQ0RFMzY2RTkwMkY3ODRFNTEzMUZBMjA1MDczMzhCRDE4RUM3QjA2NEU4QTRENEQzQjI5MkUzOTYyQkRC'
        },
        512 => {
          x: 'MDFDMzAyMEZFNkI0NkJBQUU3MTNENEVGMEI0OThFQTg1RkMzMTk3NDYwRTU4REUyNERCRTFFMUNEQzEzOUI2OTAzRUEyQkEzQzdEMzNGN0ZDNzdGMTQ2MUVCRDBFODY5QUIzMTI3RTJCNjBGNjE5QTJFMUFDNkM4M0M0ODBCRDJBRkZG',
          y: 'MDE0MkQ4MTFERjI1RjlCNTdGMDQ4REJDRjVBN0IzODUyMkQ5RDUxMEM1REE1QjYwMENGMTMyRjU4RUQ4QjZBNjFBRTFDMjVDQTYyQ0IzNTQzMzI5NUQ2QzAxQTdBNzIzODNBNEQ3MjBEOTI4NTZCNTU3NjYxMzc4RDM4OEExQkI4MjM2'
        }
      }
    end
    [256, 384, 512].each do |digest_length|
      describe "EC#{digest_length}" do
        let(:jwk) { JSON::JWK.new public_key(:ecdsa, digest_length: digest_length) }
        it { jwk.should include :alg, :crv, :x, :y }
        its(:alg) { jwk[:alg].should == :EC }
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
          alg: :RSA,
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
    end

    context 'when ECDSA' do
      it do
        expect do
          JSON::JWK.decode(
            alg: :EC,
            crv: 'crv',
            x: 'x',
            y: 'y'
          )
        end.to raise_error NotImplementedError
      end
    end

    context 'when invalid algorithm' do
      it do
        expect do
          JSON::JWK.decode(
            alg: :XXX
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
