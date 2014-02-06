require 'simplecov'

SimpleCov.start do
  add_filter 'spec'
end

require 'rspec'
require 'json/jwt'

require 'helpers/sign_key_fixture_helper'
require 'helpers/nimbus_spec_helper'