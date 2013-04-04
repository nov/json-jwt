require 'cover_me'
require 'rspec'
require 'json/jwt'

require 'helpers/sign_key_fixture_helper'

if File.exist?('helpers/json-jwt-nimbus/nimbus_jwe.rb')
  require 'helpers/json-jwt-nimbus/nimbus_jwe'
end