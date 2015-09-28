module NimbusSpecHelper
  module_function

  def setup
    nimbus_path = File.expand_path(
      File.join(
        File.dirname(__FILE__),
        'json-jwt-nimbus',
        'nimbus_jwe.rb'
      )
    )
    if File.exist? nimbus_path
      require nimbus_path
    end
  end

  def nimbus_available?
    defined? NimbusJWE
  end
end

NimbusSpecHelper.setup