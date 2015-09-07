require 'securecompare'

module JSON
  class JOSE < JWT
    include SecureCompare

    def content_type
      'application/jose'
    end

    def initialize(jwt = nil)
      update jwt if jwt
    end

    def update_with_jose_attributes(hash_or_jwt)
      update_without_jose_attributes hash_or_jwt
      if hash_or_jwt.is_a? JSON::JWT
        self.header = hash_or_jwt.header
        self.signature = hash_or_jwt.signature
      end
      self
    end
    alias_method_chain :update, :jose_attributes
  end
end