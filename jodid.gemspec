$LOAD_PATH.unshift(File.expand_path('../lib', __FILE__))
require 'jodid/version'

Gem::Specification.new do |gem|
  gem.author       = 'Hendrik Beskow'
  gem.description  = 'jodid'
  gem.summary      = gem.description
  gem.homepage     = 'https://github.com/Asmod4n/jodid'
  gem.license      = 'Apache-2.0'

  gem.name         = 'jodid'
  gem.files        = Dir['README.md', 'LICENSE', 'lib/**/*']
  gem.version      = Jodid::VERSION

  gem.required_ruby_version = '>= 1.9.3'
  gem.add_dependency 'ffi-libsodium', '>= 0.4.5'
  gem.add_development_dependency 'bundler', '>= 1.7'
end
