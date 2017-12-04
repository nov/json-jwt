require 'spec_helper'

describe 'interop' do
  describe 'with jsrsasign' do
    context 'JWS' do
      let(:public_key) do
        pem = <<-PEM.strip_heredoc
          -----BEGIN PUBLIC KEY-----
          MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoBUyo8CQAFPeYPvv78ylh5MwFZjT
          CLQeb042TjiMJxG+9DLFmRSMlBQ9T/RsLLc+PmpB1+7yPAR+oR5gZn3kJQ==
          -----END PUBLIC KEY-----
        PEM
        OpenSSL::PKey::EC.new pem
      end
      let(:private_key) do
        pem = <<-PEM.strip_heredoc
          -----BEGIN PRIVATE KEY-----
          MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEbVzfPnZPxfAyxqE
          ZV05laAoJAl+/6Xt2O4mOB611sOhRANCAASgFTKjwJAAU95g++/vzKWHkzAVmNMI
          tB5vTjZOOIwnEb70MsWZFIyUFD1P9Gwstz4+akHX7vI8BH6hHmBmfeQl
          -----END PRIVATE KEY-----
        PEM
        OpenSSL::PKey::EC.new pem
      end
      let(:jws_string) do
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTQzNTA2MjUyMywiZXhwIjoxNDM1MDY2MTIzLCJpYXQiOjE0MzUwNjI1MjMsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.HFmKrExGIFm5SwzTq_ayG80ELUIKnrR9psedV_6ZsuHl5ZLZ-1nV35o0yjKkN7qPQipQMK90xMvDYpi7e2XU9Q'
      end
      let(:payload) do
        {
          iss: 'https://jwt-idp.example.com',
          sub: 'mailto:mike@example.com',
          nbf: 1435062523,
          exp: 1435066123,
          iat: 1435062523,
          jti: 'id123456',
          typ: 'https://example.com/register'
        }
      end

      describe 'verify' do
        it 'should succeed' do
          expect do
            JSON::JWT.decode(jws_string, public_key, :ES256)
          end.not_to raise_error
        end
      end
    end
  end
end
