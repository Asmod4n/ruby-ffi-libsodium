$LOAD_PATH.unshift(File.expand_path('../lib', __FILE__))
require 'sodium/version'

Gem::Specification.new do |gem|
  gem.authors      = 'Hendrik Beskow'
  gem.description  = 'libsodium ffi wrapper'
  gem.summary      = gem.description
  gem.homepage     = 'https://github.com/Asmod4n/ruby-ffi-libsodium'
  gem.license      = 'Apache-2.0'

  gem.name         = 'ffi-libsodium'
  gem.files        = Dir['README.md', 'LICENSE', 'lib/**/*']
  gem.version      = Sodium::VERSION

  gem.required_ruby_version = '>= 1.9.3'
  gem.add_dependency 'ffi', '>= 1.9.5'
  gem.add_development_dependency 'bundler', '>= 1.7'
end
