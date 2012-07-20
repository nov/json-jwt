module JSON
  class JWK::Set < Array
    def initialize(*jwks)
      replace Array(jwks).flatten
    end

    def as_json
      {:keys => self}
    end
  end
end