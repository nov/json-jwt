require 'spec_helper'

describe JSON::JWE do
  let(:private_key_path) { der_file_path 'rsa/private_key' }

  describe '#content_type' do
    let(:jwe) { JSON::JWE.new 'hello' }
    it do
      jwe.content_type.should == 'application/jose'
    end
  end

  describe 'encrypt!' do
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

      context 'when alg=dir' do
        it :TODO
      end

      context 'when alg=A128KW' do
        it :TODO
      end

      context 'when alg=A256KW' do
        it :TODO
      end

      context 'when unknonw/unsupported algorithm given' do
        let(:key) { public_key }
        let(:alg) { :RSA1_5 }
        let(:enc) { :'A128CBC-HS256' }
        before { jwe.alg, jwe.enc = alg, enc }

        context 'when alg=unknown' do
          let(:alg) { :unknown }
          it_behaves_like :unexpected_algorithm_for_encryption
        end

        context 'when enc=unknown' do
          let(:enc) { :unknown }
          it_behaves_like :unexpected_algorithm_for_encryption
        end

        [:'ECDH-ES', :'ECDH-ES+A128KW', :'ECDH-ES+A256KW'].each do |alg|
          context "when alg=#{alg}" do
            let(:alg) { alg }
            it_behaves_like :unsupported_algorithm_for_encryption
          end
        end
      end
    end
  end

  describe 'decrypt!' do
    let(:plain_text) { 'Hello World' }
    let(:jwe_string) do
      _jwe_ = JSON::JWE.new plain_text
      _jwe_.alg, _jwe_.enc = alg, enc
      _jwe_.encrypt! key
      _jwe_.to_s
    end
    let(:jwe) do
      _jwe_ = JSON::JWE.decode jwe_string, :skip_decryption
      _jwe_.alg, _jwe_.enc = alg, enc
      _jwe_
    end

    shared_examples_for :decryptable do
      it do
        jwe.decrypt! key
        jwe.plain_text.should == plain_text
      end
    end

    shared_examples_for :verify_cbc_authentication_tag do
      let(:jwe_parts) do
        _jwe_ = JSON::JWE.new plain_text
        _jwe_.alg, _jwe_.enc = alg, enc
        _jwe_.encrypt! key
        _jwe_.to_s.split '.'
      end

      let(:hdr)         { jwe_parts[0] }
      let(:extra)       { jwe_parts[1] }
      let(:iv)          { jwe_parts[2] }
      let(:cipher_text) { jwe_parts[3] }
      let(:signature)   { jwe_parts[4] }

      let(:jwe_string) { [hdr, extra, iv, cipher_text, signature].join '.' }

      shared_examples_for :signature_verification_failure do
        it do
          # fetching those variables outside of exception block to make sure
          # we intercept exception in decrypt! and not in other place
          j = jwe
          k = key
          expect do
            j.decrypt! k
          end.to raise_error JSON::JWE::DecryptionFailed
        end
      end

      describe "with missing signature" do
        let(:signature) { "" }
        it_behaves_like :signature_verification_failure
      end

      describe "with corrupted signature" do
        let(:signature) { Base64.urlsafe_encode64(Base64.urlsafe_decode64(super()).reverse) }
        it_behaves_like :signature_verification_failure
      end
    end

    shared_examples_for :verify_gcm_authentication_tag do
      let(:jwe_string) do
        _jwe_ = JSON::JWE.new plain_text
        _jwe_.alg, _jwe_.enc = alg, enc
        _jwe_.encrypt! key
        header, key, iv, cipher_text, auth_tag = _jwe_.to_s.split('.')
        truncated_auth_tag = Base64.urlsafe_decode64(auth_tag).slice(0..-2)
        truncated_auth_tag = Base64.urlsafe_encode64(truncated_auth_tag, padding: false)
        [header, key, iv, cipher_text, truncated_auth_tag].join('.')
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
        it_behaves_like :decryptable
        it_behaves_like :verify_gcm_authentication_tag
      end

      context 'when enc=A256GCM' do
        let(:enc) { :A256GCM }
        it_behaves_like :decryptable
        it_behaves_like :verify_gcm_authentication_tag
      end

      context 'when enc=A128CBC-HS256' do
        let(:enc) { :'A128CBC-HS256' }
        it_behaves_like :decryptable
      end

      context 'when enc=A256CBC-HS512' do
        let(:enc) { :'A256CBC-HS512' }
        it_behaves_like :decryptable
      end
    end

    context 'when alg=RSA-OAEP' do
      let(:alg) { :'RSA-OAEP' }
      let(:key) { private_key }

      context 'when enc=A128GCM' do
        let(:enc) { :A128GCM }
        it_behaves_like :decryptable
        it_behaves_like :verify_gcm_authentication_tag
      end

      context 'when enc=A256GCM' do
        let(:enc) { :A256GCM }
        it_behaves_like :decryptable
        it_behaves_like :verify_gcm_authentication_tag
      end

      context 'when enc=A128CBC-HS256' do
        let(:enc) { :'A128CBC-HS256' }
        it_behaves_like :decryptable
        it_behaves_like :verify_cbc_authentication_tag
      end

      context 'when enc=A256CBC-HS512' do
        let(:enc) { :'A256CBC-HS512' }
        it_behaves_like :decryptable
        it_behaves_like :verify_cbc_authentication_tag
      end
    end

    context 'when alg=dir' do
      let(:alg) { :dir }
      let(:key) { SecureRandom.random_bytes key_size }

      context 'when enc=A128GCM' do
        let(:enc) { :A128GCM }
        let(:key_size) { 16 }
        it_behaves_like :decryptable
        it_behaves_like :verify_gcm_authentication_tag
      end

      context 'when enc=A256GCM' do
        let(:enc) { :A256GCM }
        let(:key_size) { 32 }
        it_behaves_like :decryptable
        it_behaves_like :verify_gcm_authentication_tag
      end

      context 'when enc=A128CBC-HS256' do
        let(:enc) { :'A128CBC-HS256' }
        let(:key_size) { 32 }
        it_behaves_like :decryptable
        it_behaves_like :verify_cbc_authentication_tag
      end

      context 'when enc=A256CBC-HS512' do
        let(:enc) { :'A256CBC-HS512' }
        let(:key_size) { 64 }
        it_behaves_like :decryptable
        it_behaves_like :verify_cbc_authentication_tag
      end
    end

    context 'when alg=A128KW' do
      it :TODO
    end

    context 'when alg=A256KW' do
      it :TODO
    end

    context 'when unknonw/unsupported algorithm given' do
      let(:input) { 'header.key.iv.cipher_text.auth_tag' }
      let(:key) { public_key }
      let(:alg) { :RSA1_5 }
      let(:enc) { :'A128CBC-HS256' }

      context 'when alg=unknown' do
        let(:alg) { :unknown }
        it_behaves_like :unexpected_algorithm_for_decryption
      end

      context 'when enc=unknown' do
        let(:enc) { :unknown }
        it_behaves_like :unexpected_algorithm_for_decryption
      end

      [:'ECDH-ES', :'ECDH-ES+A128KW', :'ECDH-ES+A256KW'].each do |alg|
        context "when alg=#{alg}" do
          let(:alg) { alg }
          it_behaves_like :unsupported_algorithm_for_decryption
        end
      end
    end
  end
end
