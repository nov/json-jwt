module NimbusSpecHelper
  module_function

  def setup
    nimbus_path = File.expand_path(
      File.join(
        File.dirname(__FILE__),
        'json-jwt-nimbus'
      )
    )
    if File.exist? nimbus_path
      require File.join(nimbus_path, 'nimbus_jwe')
    end
  end

  def nimbus_available?
    defined? NimbusJWE
  end
end

NimbusSpecHelper.setup