module SignKeyFixtureHelper
  def shared_secret
    'shared-secret'
  end

  def pem_file(file_name)
    File.new(
      File.join(
        File.dirname(__FILE__),
        '../fixtures/rsa',
        "#{file_name}.pem"
      )
    )
  end

  def private_key
    OpenSSL::PKey::RSA.new(
      pem_file('private_key'),
      'pass-phrase'
    )
  end

  def public_key
    OpenSSL::PKey::RSA.new(
      pem_file('public_key')
    )
  end
end

include SignKeyFixtureHelper