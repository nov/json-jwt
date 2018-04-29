Gem::Specification.new do |gem|
  gem.name        = 'json-jwt'
  gem.version     = File.read('VERSION')
  gem.authors     = ['nov matake']
  gem.email       = ['nov@matake.jp']
  gem.homepage    = 'https://github.com/nov/json-jwt'
  gem.summary     = %q{JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby}
  gem.description = %q{JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby}
  gem.license     = 'MIT'
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ['lib']
  gem.add_runtime_dependency 'activesupport'
  gem.add_runtime_dependency 'bindata'
  gem.add_runtime_dependency 'aes_key_wrap'
  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'rspec'
  gem.add_development_dependency 'rspec-its'
end
