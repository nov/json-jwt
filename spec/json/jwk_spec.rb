require 'spec_helper'

describe JSON::JWK do
  context 'when RSA public key given' do
    let(:jwk) { JSON::JWK.new public_key }
    it { jwk.should include :alg, :exp, :mod }
    its(:alg) { jwk[:alg].should == :RSA }
    its(:exp) { jwk[:exp].should == UrlSafeBase64.encode64(public_key.e.to_s(2)) }
    its(:mod) { jwk[:mod].should == UrlSafeBase64.encode64(public_key.n.to_s(2)) }

    context 'when kid/use options given' do
      let(:jwk) { JSON::JWK.new public_key, :kid => '12345', :use => :sig }
      it { jwk.should include :kid, :use }
      its(:kid) { jwk[:kid].should == '12345' }
      its(:use) { jwk[:use].should == :sig }
    end
  end

  context 'when ECDSA public key given' do
    let(:expected_coodinates) do
      {
        256 => {
          :x => 'OTUyMUU1NjJFOEQ3NDA0MTRDOEEyQjk5RDQ2NkZERDVFNUYwQzUzMUFGNENBNkMxMTY2Q0NFQzUzQjVGRDMwRg',
          :y => 'MDIwQTRENTQwN0ExQkJFNzQwNkJDNjIyMUI5NjUxQTY1NjY5Mjg4QUU1OEE1NjRDNjcwN0Q1RkQ5REM3MDlCNw'
        },
        384 => {
          :x => 'QTY1Q0MwQTcyMTY3MkJCQUIzODYwRTU3OUM4NjVCMTYzREExNjY4MUY2NTVEOTc4RjkxMTY2RUMzOUVDMzRDMUJEQjcyQUFCQTVGQUI2NDcyOERGMjgwMDVCNzA1NDZE',
          :y => 'OEIxMDczN0RGODY0RERGNzFCOTlFOEE5MThCOTJGNDAxMzQyQ0RFMzY2RTkwMkY3ODRFNTEzMUZBMjA1MDczMzhCRDE4RUM3QjA2NEU4QTRENEQzQjI5MkUzOTYyQkRC'
        },
        512 => {
          :x => 'MDFDMzAyMEZFNkI0NkJBQUU3MTNENEVGMEI0OThFQTg1RkMzMTk3NDYwRTU4REUyNERCRTFFMUNEQzEzOUI2OTAzRUEyQkEzQzdEMzNGN0ZDNzdGMTQ2MUVCRDBFODY5QUIzMTI3RTJCNjBGNjE5QTJFMUFDNkM4M0M0ODBCRDJBRkZG',
          :y => 'MDE0MkQ4MTFERjI1RjlCNTdGMDQ4REJDRjVBN0IzODUyMkQ5RDUxMEM1REE1QjYwMENGMTMyRjU4RUQ4QjZBNjFBRTFDMjVDQTYyQ0IzNTQzMzI5NUQ2QzAxQTdBNzIzODNBNEQ3MjBEOTI4NTZCNTU3NjYxMzc4RDM4OEExQkI4MjM2'
        }
      }
    end
    [256, 384, 512].each do |digest_length|
      describe "EC#{digest_length}" do
        let(:jwk) { JSON::JWK.new public_key(:ecdsa, :digest_length => digest_length) }
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
        end.to raise_error JSON::JWK::UnknownAlgorighm, 'Unknown ECDSA Curve'
      end
    end
  end

  describe 'unknown algorithm' do
    it do
      key = OpenSSL::PKey::DSA.generate 256
      expect do
        JSON::JWK.new key
      end.to raise_error JSON::JWK::UnknownAlgorighm, 'Unknown Algorithm'
    end
  end
end