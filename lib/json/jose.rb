module JSON
  class JOSE < JWT
    def content_type
      'application/jose'
    end
  end
end