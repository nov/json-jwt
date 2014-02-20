require 'securecompare'

module JSON
  class JOSE < JWT
    include SecureCompare

    def content_type
      'application/jose'
    end
  end
end