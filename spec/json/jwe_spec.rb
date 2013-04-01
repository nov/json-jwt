require 'spec_helper'

describe JSON::JWE do
  let(:plain_text) { 'Hello World' }
  let(:jwe) { JSON::JWE.new plain_text }

  describe 'encrypt!' do
    context 'when alg=RSA-OAEP' do
      before do
        jwe.alg = :'RSA1_5'
      end

      context 'when enc=A128GCM' do
        before do
          jwe.enc = :A128GCM
        end

        it do
          jwe.encrypt! public_key
          p jwe.to_s
        end
      end

      context 'when enc=A256GCM' do
        before do
          jwe.enc = :A256GCM
        end

        it do
          jwe.encrypt! public_key
          p jwe.to_s
        end
      end
    end

    context 'when alg=RSA-OAEP' do
      before do
        jwe.alg = :'RSA-OAEP'
      end

      context 'when enc=A128GCM' do
        before do
          jwe.enc = :A128GCM
        end

        it do
          jwe.encrypt! public_key
          p jwe.to_s
        end
      end

      context 'when enc=A256GCM' do
        before do
          jwe.enc = :A256GCM
        end

        it do
          jwe.encrypt! public_key
          p jwe.to_s
        end
      end
    end

    context 'when alg=dir' do
      before do
        jwe.alg = :dir
      end

      context 'when enc=A128GCM' do
        before do
          jwe.enc = :A128GCM
        end

        it do
          jwe.encrypt! shared_secret
          p jwe.to_s
        end
      end

      context 'when enc=A256GCM' do
        before do
          jwe.enc = :A256GCM
        end

        it do
          jwe.encrypt! shared_secret
          p jwe.to_s
        end
      end
    end
  end
end
