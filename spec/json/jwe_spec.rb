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

    shared_examples_for :unexpected_algorithm_for_encryption do
      it do
        expect do
          jwe.encrypt!(key).to_s # NOTE: encrypt! won't raise, but to_s does. might need to fix.
        end.to raise_error JSON::JWE::UnexpectedAlgorithm
      end
    end

    shared_examples_for :unsupported_algorithm_for_encryption do
      it do
        expect do
          jwe.encrypt!(key).to_s # NOTE: encrypt! won't raise, but to_s does. might need to fix.
        end.to raise_error NotImplementedError
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

      context 'when unknonw/unsupported algorithm given' do
        let(:key) { public_key }
        let(:alg) { :RSA1_5 }
        let(:enc) { :'A128CBC+HS256' }
        before { jwe.alg, jwe.enc = alg, enc }

        context 'when alg=unknown' do
          let(:alg) { :unknown }
          it_behaves_like :unexpected_algorithm_for_encryption
        end

        context 'when enc=unknown' do
          let(:enc) { :unknown }
          it_behaves_like :unexpected_algorithm_for_encryption
        end

        [:A128KW, :A256KW, :'ECDH-ES', :'ECDH-ES+A128KW', :'ECDH-ES+A256KW'].each do |alg|
          context "when alg=#{alg}" do
            let(:alg) { alg }
            it_behaves_like :unsupported_algorithm_for_encryption
          end
        end
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
    end
  end

  describe 'decrypt!' do
    let(:plain_text) { 'Hello World' }
    let(:input) do
      _jwe_ = JSON::JWE.new plain_text
      _jwe_.alg, _jwe_.enc = alg, enc
      _jwe_.encrypt! key
      _jwe_.to_s
    end
    let(:jwe) do
      _jwe_ = JSON::JWE.new input
      _jwe_.alg, _jwe_.enc = alg, enc
      _jwe_
    end

    shared_examples_for :decryptable do
      it do
        jwe.decrypt! key
        jwe.to_s.should == plain_text
      end
    end

    shared_examples_for :gcm_decryption_unsupported do
      it do
        expect do
          jwe.decrypt! key
        end.to raise_error JSON::JWE::UnexpectedAlgorithm
      end
    end

    shared_examples_for :verify_cbc_integrity_value do
      let(:input) do
        _jwe_ = JSON::JWE.new plain_text
        _jwe_.alg, _jwe_.enc = alg, enc
        _jwe_.encrypt! key
        _jwe_.to_s + 'tampered'
      end

      it do
        expect do
          jwe.decrypt! key
        end.to raise_error JSON::JWE::DecryptionFailed
      end
    end

    shared_examples_for :unexpected_algorithm_for_decryption do
      it do
        expect do
          jwe.decrypt! key
        end.to raise_error JSON::JWE::UnexpectedAlgorithm
      end
    end

    shared_examples_for :unsupported_algorithm_for_decryption do
      it do
        expect do
          jwe.decrypt! key
        end.to raise_error NotImplementedError
      end
    end

    context 'when alg=RSA1_5' do
      let(:alg) { :RSA1_5 }
      let(:key) { private_key }

      context 'when enc=A128GCM' do
        let(:enc) { :A128GCM }
        if gcm_supported?
          it_behaves_like :decryptable
        else
          it_behaves_like :gcm_decryption_unsupported
        end
      end

      context 'when enc=A256GCM' do
        let(:enc) { :A256GCM }
        if gcm_supported?
          it_behaves_like :decryptable
        else
          it_behaves_like :gcm_decryption_unsupported
        end
      end

      context 'when enc=A128CBC+HS256' do
        let(:enc) { :'A128CBC+HS256' }
        it_behaves_like :decryptable
      end

      context 'when enc=A256CBC+HS512' do
        let(:enc) { :'A256CBC+HS512' }
        it_behaves_like :decryptable
      end
    end

    context 'when alg=RSA-OAEP' do
      let(:alg) { :'RSA-OAEP' }
      let(:key) { private_key }

      context 'when enc=A128GCM' do
        let(:enc) { :A128GCM }
        if gcm_supported?
          it_behaves_like :decryptable
        else
          it_behaves_like :gcm_decryption_unsupported
        end
      end

      context 'when enc=A256GCM' do
        let(:enc) { :A256GCM }
        if gcm_supported?
          it_behaves_like :decryptable
        else
          it_behaves_like :gcm_decryption_unsupported
        end
      end

      context 'when enc=A128CBC+HS256' do
        let(:enc) { :'A128CBC+HS256' }
        it_behaves_like :decryptable
        it_behaves_like :verify_cbc_integrity_value
      end

      context 'when enc=A256CBC+HS512' do
        let(:enc) { :'A256CBC+HS512' }
        it_behaves_like :decryptable
        it_behaves_like :verify_cbc_integrity_value
      end
    end

    context 'when alg=dir' do
      let(:alg) { :dir }
      let(:key) { 'todo' }
      it :TODO
    end

    context 'when unknonw/unsupported algorithm given' do
      let(:input) { 'whatever' }
      let(:key) { public_key }
      let(:alg) { :RSA1_5 }
      let(:enc) { :'A128CBC+HS256' }

      context 'when alg=unknown' do
        let(:alg) { :unknown }
        it_behaves_like :unexpected_algorithm_for_decryption
      end

      context 'when enc=unknown' do
        let(:enc) { :unknown }
        it_behaves_like :unexpected_algorithm_for_decryption
      end

      [:A128KW, :A256KW, :'ECDH-ES', :'ECDH-ES+A128KW', :'ECDH-ES+A256KW'].each do |alg|
        context "when alg=#{alg}" do
          let(:alg) { alg }
          it_behaves_like :unsupported_algorithm_for_decryption
        end
      end
    end
  end
end
