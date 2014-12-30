$LOAD_PATH.unshift(File.expand_path('../lib', __FILE__))
require 'iodine/version'

Gem::Specification.new do |gem|
  gem.author       = 'Hendrik Beskow'
  gem.description  = 'iodine'
  gem.summary      = gem.description
  gem.homepage     = 'https://github.com/Asmod4n/iodine'
  gem.license      = 'Apache-2.0'

  gem.name         = 'iodine'
  gem.files        = Dir['README.md', 'LICENSE', 'lib/**/*']
  gem.version      = Iodine::VERSION

  gem.required_ruby_version = '>= 1.9.3'
  gem.add_dependency 'ffi-libsodium', '>= 0.4.5'
  gem.add_dependency 'ffi-czmq', '>= 0.1.6.pre'
  gem.add_development_dependency 'bundler', '>= 1.7'
end
