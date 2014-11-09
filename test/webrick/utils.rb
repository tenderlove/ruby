require_relative '../ruby/envutil'
require "webrick"
begin
  require "webrick/https"
rescue LoadError
end
require "webrick/httpproxy"

module TestWEBrick
  NullWriter = Object.new
  def NullWriter.<<(msg)
    puts msg if $DEBUG
    return self
  end

  class WEBrick::HTTPServlet::CGIHandler
    remove_const :Ruby
    Ruby = EnvUtil.rubybin
    remove_const :CGIRunner
    CGIRunner = "\"#{Ruby}\" \"#{WEBrick::Config::LIBDIR}/httpservlet/cgi_runner.rb\"" # :nodoc:
  end

  RubyBin = "\"#{EnvUtil.rubybin}\""
  RubyBin << " --disable-gems"
  RubyBin << " \"-I#{File.expand_path("../..", File.dirname(__FILE__))}/lib\""
  RubyBin << " \"-I#{File.dirname(EnvUtil.rubybin)}/.ext/common\""
  RubyBin << " \"-I#{File.dirname(EnvUtil.rubybin)}/.ext/#{RUBY_PLATFORM}\""

  include Test::Unit::Assertions
  extend Test::Unit::Assertions

  module_function

  def start_server(klass, config={}, &block)
    log_ary = []
    log = proc { "webrick log start:\n" + log_ary.join.gsub(/^/, "  ").chomp + "\nwebrick log end" }
    server = klass.new({
      :BindAddress => "127.0.0.1", :Port => 0,
      :ServerType => Thread,
      :Logger => WEBrick::Log.new(log_ary, WEBrick::BasicLog::WARN),
      :AccessLog => [[log_ary, ""]]
    }.update(config))
    server_thread = server.start
    addr = server.listeners[0].addr
    client_thread = Thread.new {
      begin
        block.yield([server, addr[3], addr[1], log])
      ensure
        server.shutdown
      end
    }
    assert_join_threads([client_thread, server_thread])
    log_ary
  end

  def start_httpserver(config={}, &block)
    start_server(WEBrick::HTTPServer, config, &block)
  end

  def start_httpproxy(config={}, &block)
    start_server(WEBrick::HTTPProxyServer, config, &block)
  end
end
