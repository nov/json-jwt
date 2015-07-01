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
  RUBY_VERSION >= '2.0.0' && (OpenSSL::OPENSSL_VERSION >= 'OpenSSL 1.0.1c' ||
      OpenSSL::OPENSSL_VERSION == 'OpenSSL 1.0.1 14 Mar 2012')
end

require 'helpers/sign_key_fixture_helper'
require 'helpers/nimbus_spec_helper'
