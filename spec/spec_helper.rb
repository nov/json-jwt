require 'rspec'
require 'json/jwt'

def rsa
  @rsa ||= OpenSSL::PKey::RSA.generate 2048
end

def public_key
  @public_key ||= rsa.public_key
end

def private_key
  @private_key ||= OpenSSL::PKey::RSA.new rsa.export(OpenSSL::Cipher::Cipher.new('DES-EDE3-CBC'), 'pass-phrase'), 'pass-phrase'
end

def shared_secret
  'shared-secret'
end