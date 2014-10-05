$LOAD_PATH.unshift(File.expand_path('../lib', __FILE__))
require 'sodium/version'
require 'digest/sha2'
require 'fileutils'

gem_name = "ffi-libsodium-#{Sodium::VERSION}.gem"
checksum = Digest::SHA2.new.hexdigest(File.read(gem_name))
FileUtils.mkdir_p('checksum')
checksum_path = "checksum/#{gem_name}.sha2"
File.open(checksum_path, 'w' ) {|f| f.write(checksum) }
