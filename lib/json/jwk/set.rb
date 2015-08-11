module JSON
  class JWK
    class Set < Array
      def initialize(*jwks)
        jwks = Array(jwks).flatten.collect do |jwk|
          JWK.new jwk
        end
        replace jwks
      end

      def content_type
        'application/jwk-set+json'
      end

      def as_json(options = {})
        # NOTE: Array.new wrapper is requied to avoid CircularReferenceError
        {keys: Array.new(self)}
      end
    end
  end
end