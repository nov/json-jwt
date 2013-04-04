require 'spec_helper'

def gcm_supported?
  RUBY_VERSION >= '2.0.0' && OpenSSL::OPENSSL_VERSION >= 'OpenSSL 1.0.1c'
end

describe JSON::JWE do
  let(:shared_key) { SecureRandom.hex 16 } # default shared key is too short
  let(:private_key_path) { der_file_path 'rsa/private_key' }

  describe 'encrypt!' do
    shared_examples_for :gcm_encryption do
      context 'when enc=A128GCM' do
        before { jwe.enc = :A128GCM }

        it 'should decryptable by Nimbus JOSE JWT' do
          jwe.encrypt! key
          NimbusJWE.decrypt(jwe, private_key_path).should == plain_text
        end
      end

      context 'when enc=A256GCM' do
        before { jwe.enc = :A256GCM }

        it 'should decryptable by Nimbus JOSE JWT' do
          jwe.encrypt! key
          NimbusJWE.decrypt(jwe, private_key_path).should == plain_text
        end
      end
    end

    shared_examples_for :gcm_encryption_unsupported do
      context 'when enc=A128GCM' do
        before { jwe.enc = :A128GCM }

        it do
          expect do
            jwe.encrypt! key
          end.to raise_error JSON::JWE::UnexpectedAlgorithm
        end
      end

      context 'when enc=A256GCM' do
        before { jwe.enc = :A256GCM }

        it do
          expect do
            jwe.encrypt! key
          end.to raise_error JSON::JWE::UnexpectedAlgorithm
        end
      end
    end

    shared_examples_for :cbc_encryption do
      context 'when enc=A128CBC+HS256' do
        before { jwe.enc = :'A128CBC+HS256' }

        it 'should decryptable by Nimbus JOSE JWT' do
          jwe.encrypt! key
          NimbusJWE.decrypt(jwe, private_key_path).should == plain_text
        end
      end

      context 'when enc=A256CBC+HS512' do
        before { jwe.enc = :'A256CBC+HS512' }

        it 'should decryptable by Nimbus JOSE JWT' do
          jwe.encrypt! key
          NimbusJWE.decrypt(jwe, private_key_path).should == plain_text
        end
      end
    end

    context 'when plaintext given' do
      let(:plain_text) { 'Hello World' }
      let(:jwe) { JSON::JWE.new plain_text }

      context 'when alg=RSA1_5' do
        if NimbusSpecHelper.nimbus_available?
          let(:key) { public_key }
          before { jwe.alg = :'RSA1_5' }

          if gcm_supported?
            it_behaves_like :gcm_encryption
          else
            it_behaves_like :gcm_encryption_unsupported
          end
          it_behaves_like :cbc_encryption
        else
          it :TODO
        end
      end

      context 'when alg=RSA-OAEP' do
        if NimbusSpecHelper.nimbus_available?
          let(:key) { public_key }
          before { jwe.alg = :'RSA-OAEP' }

          if gcm_supported?
            it_behaves_like :gcm_encryption
          else
            it_behaves_like :gcm_encryption_unsupported
          end
          it_behaves_like :cbc_encryption
        else
          it :TODO
        end
      end

      context 'when alg=dir' do
        it :TODO
      end
    end

    context 'when jwt given' do
      let(:plain_text) { jwt.to_s }
      let(:jwt) { JSON::JWT.new(foo: :bar) }
      let(:jwe) { JSON::JWE.new jwt }

      context 'when alg=RSA-OAEP' do
        if NimbusSpecHelper.nimbus_available?
          let(:key) { public_key }
          before { jwe.alg = :'RSA1_5' }

          if gcm_supported?
            it_behaves_like :gcm_encryption
          else
            it_behaves_like :gcm_encryption_unsupported
          end
          it_behaves_like :cbc_encryption
        else
          it :TODO
        end
      end

      context 'when alg=RSA-OAEP' do
        if NimbusSpecHelper.nimbus_available?
          let(:key) { public_key }
          before { jwe.alg = :'RSA-OAEP' }

          if gcm_supported?
            it_behaves_like :gcm_encryption
          else
            it_behaves_like :gcm_encryption_unsupported
          end
          it_behaves_like :cbc_encryption
        else
          it :TODO
        end
      end

      context 'when alg=dir' do
        it :TODO
      end
    end
  end

  describe 'decrypt!' do
    let(:plain_text) { 'hello' }
    let(:input) do
      _jwe_ = JSON::JWE.new plain_text
      _jwe_.alg, _jwe_.enc = alg, enc
      _jwe_.encrypt! private_key
      _jwe_.to_s
    end
    let(:jwe) do
      _jwe_ = JSON::JWE.new input
      _jwe_.alg, _jwe_.enc = alg, enc
      _jwe_
    end

    shared_examples_for :private_key_decryptable do
      it do
        jwe.decrypt! private_key
        jwe.to_s.should == plain_text
      end
    end

    context 'when alg=RSA1_5' do
      let(:alg) { :RSA1_5 }

      context 'when enc=A128GCM' do
        let(:enc) { :A128GCM }
        it_behaves_like :private_key_decryptable
      end

      context 'when enc=A256GCM' do
        let(:enc) { :A256GCM }
        it_behaves_like :private_key_decryptable
      end

      context 'when enc=A128CBC+HS256' do
        let(:enc) { :'A128CBC+HS256' }
        it :TODO
      end

      context 'when enc=A256CBC+HS512' do
        let(:enc) { :'A256CBC+HS512' }
        it :TODO
      end
    end

    context 'when alg=RSA-OAEP' do
      let(:alg) { :'RSA-OAEP' }

      context 'when enc=A128GCM' do
        let(:enc) { :A128GCM }
        it_behaves_like :private_key_decryptable
      end

      context 'when enc=A256GCM' do
        let(:enc) { :A256GCM }
        it_behaves_like :private_key_decryptable
      end

      context 'when enc=A128CBC+HS256' do
        let(:enc) { :'A128CBC+HS256' }
        it :TODO
      end

      context 'when enc=A256CBC+HS512' do
        let(:enc) { :'A256CBC+HS512' }
        it :TODO
      end
    end
  end
end
