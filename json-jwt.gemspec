Gem::Specification.new do |s|
  s.name        = "json-jwt"
  s.version     = File.read("VERSION")
  s.authors     = ["nov matake"]
  s.email       = ["nov@matake.jp"]
  s.homepage    = "https://github.com/nov/json-jwt"
  s.summary     = %q{JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby}
  s.description = %q{JSON Web Token and its family (JSON Web Signature, JSON Web Encryption and JSON Web Key) in Ruby}
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.add_runtime_dependency "json", ">= 1.4.3"
  s.add_runtime_dependency "url_safe_base64"
  s.add_development_dependency "rake", ">= 0.8"
  s.add_development_dependency "rcov", ">= 0.9"
  s.add_development_dependency "rspec", ">= 2"
end