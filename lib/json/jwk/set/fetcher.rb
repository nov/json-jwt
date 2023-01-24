module JSON
  class JWK
    class Set
      module Fetcher
        class Cache
          def fetch(cache_key, options = {})
            yield
          end

          def delete(cache_key, options = {}); end
        end

        def self.logger
          @@logger
        end
        def self.logger=(logger)
          @@logger = logger
        end
        self.logger = Logger.new(STDOUT)
        self.logger.progname = 'JSON::JWK::Set::Fetcher'

        def self.debugging?
          @@debugging
        end
        def self.debugging=(boolean)
          @@debugging = boolean
        end
        def self.debug!
          self.debugging = true
        end
        def self.debug(&block)
          original = self.debugging?
          debug!
          yield
        ensure
          self.debugging = original
        end
        self.debugging = false

        def self.http_client
          Faraday.new(headers: {user_agent: "JSON::JWK::Set::Fetcher #{VERSION}"}) do |faraday|
            faraday.response :raise_error
            faraday.response :follow_redirects
            faraday.response :logger, JSON::JWK::Set::Fetcher.logger if debugging?
            faraday.adapter Faraday.default_adapter
            http_config.try(:call, faraday)
          end
        end
        def self.http_config(&block)
          @@http_config ||= block
        end

        def self.cache=(cache)
          @@cache = cache
        end
        def self.cache
          @@cache
        end
        self.cache = Cache.new

        def self.fetch(jwks_uri, kid:, auto_detect: true, **options)
          cache_key = [
            'json:jwk:set',
            OpenSSL::Digest::MD5.hexdigest(jwks_uri),
            kid
          ].collect(&:to_s).join(':')

          jwks = Set.new(
            JSON.parse(
              cache.fetch(cache_key, options) do
                http_client.get(jwks_uri).body
              end
            )
          )
          cache.delete(cache_key, options) if jwks[kid].blank?

          if auto_detect
            jwks[kid] or raise KidNotFound
          else
            jwks
          end
        end
      end
    end
  end
end