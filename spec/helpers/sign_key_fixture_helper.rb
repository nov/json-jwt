module SignKeyFixtureHelper
  def shared_secret
    'shared-secret'
  end

  def pem_file(file_name)
    File.new(
      File.join(
        File.dirname(__FILE__),
        "../fixtures/#{file_name}.pem"
      )
    )
  end

  def private_key(algorithm = :rsa, options = {})
    case algorithm
    when :rsa
      OpenSSL::PKey::RSA.new(
        pem_file("#{algorithm}/private_key"),
        'pass-phrase'
      )
    when :ecdsa
      OpenSSL::PKey::RSA.new(
        pem_file("#{algorithm}/#{options[:degree]}/private_key")
      )
    end
  end

  def public_key(algorithm = :rsa, options = {})
    case algorithm
    when :rsa
      OpenSSL::PKey::RSA.new(
        pem_file("#{algorithm}/public_key")
      )
    when :ecdsa
      OpenSSL::PKey::RSA.new(
        pem_file("#{algorithm}/#{options[:degree]}/public_key")
      )
    end
  end
end

include SignKeyFixtureHelper