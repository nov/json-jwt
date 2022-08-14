module JSON
  class JWK
    class Set
      module Fetcher
        class Cache
          def fetch(cache_key, options = {})
            yield
          end
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
          _http_client_ = HTTPClient.new(
            agent_name: "JSON::JWK::Set::Fetcher (#{JSON::JWT::VERSION})"
          )

          # NOTE: httpclient gem seems stopped maintaining root certtificate set, use OS default.
          _http_client_.ssl_config.clear_cert_store
          _http_client_.ssl_config.cert_store.set_default_paths

          _http_client_.request_filter << Debugger::RequestFilter.new if debugging?
          http_config.try(:call, _http_client_)
          _http_client_
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
                http_client.get_content(jwks_uri)
              end
            )
          )

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