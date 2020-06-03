module SignKeyFixtureHelper
  def shared_secret
    'shared-secret'
  end

  def pem_file(file_name)
    File.new pem_file_path(file_name)
  end

  def pem_file_path(file_name)
    File.join(
      File.dirname(__FILE__),
      "../fixtures/#{file_name}.pem"
    )
  end

  def der_file_path(file_name)
    File.join(
      File.dirname(__FILE__),
      "../fixtures/#{file_name}.der"
    )
  end

  def private_key(algorithm = :rsa, digest_length: 256, curve_name: nil)
    case algorithm
    when :rsa
      OpenSSL::PKey::RSA.new(
        pem_file("#{algorithm}/private_key"),
        'pass-phrase'
      )
    when :ecdsa
      OpenSSL::PKey::EC.new(
        pem_file(
          File.join([
            algorithm,
            digest_length,
            curve_name,
            'private_key',
          ].compact.collect(&:to_s))
        )
      )
    end
  end

  def public_key(algorithm = :rsa, digest_length: 256, curve_name: nil)
    case algorithm
    when :rsa
      OpenSSL::PKey::RSA.new(
        pem_file("#{algorithm}/public_key")
      )
    when :ecdsa
      OpenSSL::PKey::EC.new(
        pem_file(
          File.join([
            algorithm,
            digest_length,
            curve_name,
            'public_key',
          ].compact.collect(&:to_s))
        )
      )
    end
  end
end

include SignKeyFixtureHelper