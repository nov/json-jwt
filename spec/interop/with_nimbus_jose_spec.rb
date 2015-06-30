require 'spec_helper'

describe 'interop' do
  describe 'with Nimbus JOSE' do
    if NimbusSpecHelper.nimbus_available?
      context 'JWE' do
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

          shared_examples_for :cbc_encryption do
            context 'when enc=A128CBC-HS256' do
              before { jwe.enc = :'A128CBC-HS256' }

              it 'should decryptable by Nimbus JOSE JWT' do
                jwe.encrypt! key
                NimbusJWE.decrypt(jwe, private_key_path).should == plain_text
              end
            end

            context 'when enc=A256CBC-HS512' do
              before { jwe.enc = :'A256CBC-HS512' }

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
              let(:key) { public_key }
              before { jwe.alg = :'RSA1_5' }

              it_behaves_like :gcm_encryption if gcm_supported?
              it_behaves_like :cbc_encryption
            end

            context 'when alg=RSA-OAEP' do
              let(:key) { public_key }
              before { jwe.alg = :'RSA-OAEP' }

              it_behaves_like :gcm_encryption if gcm_supported?
              it_behaves_like :cbc_encryption
            end
          end

          context 'when jwt given' do
            let(:plain_text) { jwt.to_s }
            let(:jwt) { JSON::JWT.new(foo: :bar) }
            let(:jwe) { JSON::JWE.new jwt }

            context 'when alg=RSA-OAEP' do
              let(:key) { public_key }
              before { jwe.alg = :'RSA1_5' }

              it_behaves_like :gcm_encryption if gcm_supported?
              it_behaves_like :cbc_encryption
            end

            context 'when alg=RSA-OAEP' do
              let(:key) { public_key }
              before { jwe.alg = :'RSA-OAEP' }

              it_behaves_like :gcm_encryption if gcm_supported?
              it_behaves_like :cbc_encryption
            end
          end
        end
      end
    else
      skip 'Nimbus JOSE unavailable'
    end
  end
end
