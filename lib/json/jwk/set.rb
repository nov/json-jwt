module JSON
  class JWK::Set < Array
    def initialize(*jwks)
      replace Array(jwks).flatten
    end

    def content_type
      'application/jwk-set+json'
    end

    def as_json(options = {})
      # NOTE: Array.new wrapper is requied to avoid CircularReferenceError
      { :keys => Array.new(self) }
    end
  end
end