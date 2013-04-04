require 'spec_helper'

def gcm_supported?
  RUBY_VERSION >= '2.0.0' && OpenSSL::OPENSSL_VERSION >= 'OpenSSL 1.0.1c'
end

describe JSON::JWE do
  let(:shared_key) { SecureRandom.hex 16 } # default shared key is too short

  describe 'encrypt!' do
    shared_examples_for :gcm_encryption do
      context 'when enc=A128GCM' do
        before { jwe.enc = :A128GCM }

        it do
          jwe.encrypt! key
          p jwe.to_s
        end
      end

      context 'when enc=A256GCM' do
        before { jwe.enc = :A256GCM }

        it do
          jwe.encrypt! key
          p jwe.to_s
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

        it do
          jwe.encrypt! key
          p jwe.to_s
        end
      end

      context 'when enc=A256CBC+HS512' do
        before { jwe.enc = :'A256CBC+HS512' }

        it do
          jwe.encrypt! key
          p jwe.to_s
        end
      end
    end

    context 'when plaintext given' do
      let(:plain_text) { 'Hello World' }
      let(:jwe) { JSON::JWE.new plain_text }

      context 'when alg=RSA1_5' do
        let(:key) { public_key }
        before { jwe.alg = :'RSA1_5' }

        if gcm_supported?
          it_behaves_like :gcm_encryption
        else
          it_behaves_like :gcm_encryption_unsupported
        end
        it_behaves_like :cbc_encryption
      end

      context 'when alg=RSA-OAEP' do
        let(:key) { public_key }
        before { jwe.alg = :'RSA-OAEP' }

        if gcm_supported?
          it_behaves_like :gcm_encryption
        else
          it_behaves_like :gcm_encryption_unsupported
        end
        it_behaves_like :cbc_encryption
      end

      context 'when alg=dir' do
        let(:key) { SecureRandom.hex 16 }
        before { jwe.alg = :dir }

        if gcm_supported?
          it_behaves_like :gcm_encryption

          it 'should use given key directly' do
            jwe.enc = :A256GCM
            jwe.master_key.should be_nil
            jwe.encrypt! key
            jwe.master_key.should == key
            jwe.send(:encrypted_master_key).should == ''
          end
        else
          it_behaves_like :gcm_encryption_unsupported
        end
        it_behaves_like :cbc_encryption
      end
    end

    context 'when jwt given' do
      let(:jwt) { JSON::JWT.new(foo: :bar) }
      let(:jwe) { JSON::JWE.new jwt }

      context 'when alg=RSA-OAEP' do
        let(:key) { public_key }
        before { jwe.alg = :'RSA1_5' }

        if gcm_supported?
          it_behaves_like :gcm_encryption
        else
          it_behaves_like :gcm_encryption_unsupported
        end
        it_behaves_like :cbc_encryption
      end

      context 'when alg=RSA-OAEP' do
        let(:key) { public_key }
        before { jwe.alg = :'RSA-OAEP' }

        if gcm_supported?
          it_behaves_like :gcm_encryption
        else
          it_behaves_like :gcm_encryption_unsupported
        end
        it_behaves_like :cbc_encryption
      end

      context 'when alg=dir' do
        let(:key) { shared_key }
        before { jwe.alg = :dir }

        if gcm_supported?
          it_behaves_like :gcm_encryption

          it 'should use given key directly' do
            jwe.enc = :A256GCM
            jwe.master_key.should be_nil
            jwe.encrypt! key
            jwe.master_key.should == key
            jwe.send(:encrypted_master_key).should == ''
          end
        else
          it_behaves_like :gcm_encryption_unsupported
        end
        it_behaves_like :cbc_encryption
      end
    end
  end
end
