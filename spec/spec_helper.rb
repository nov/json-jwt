require 'simplecov'

SimpleCov.start do
  add_filter 'spec'
end

require 'rspec'
require 'rspec/its'
require 'json/jwt'

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = [:should, :expect]
  end
end

def gcm_supported?
  ['aes-128-gcm', 'aes-128-gcm'].all? do |alg|
    OpenSSL::Cipher.ciphers.include? alg
  end
end

require 'helpers/sign_key_fixture_helper'
require 'helpers/nimbus_spec_helper'

puts "Running with OpenSSL::OPENSSL_VERSION=#{OpenSSL::OPENSSL_VERSION}"
