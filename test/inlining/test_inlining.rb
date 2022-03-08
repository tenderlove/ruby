# frozen_string_literal: false
require 'test/unit'

class TestInlining < Test::Unit::TestCase
  def foo(a); a + 1; end
  def bar; foo(9); end

  def test_enable_inlining
    reader, writer = IO.pipe
    Process.waitpid fork {
      reader.close
      RubyVM.enable_inlining!

      3.times do
        bar
      end

      disasm = RubyVM::InstructionSequence.disasm(method(:bar))
      writer.write(Marshal.dump(disasm))
    }

    writer.close
    disasm = Marshal.load(reader.read)

    expected_disasm = <<~HEREDOC
      0000 putself
      0001 putobject                              9
      0003 jump_if_cache_miss                     <calldata!mid:foo, argc:1, FCALL|ARGS_SIMPLE>, 16
      0006 setlocal_WC_0                          ?@0
      0008 pop
      0009 getlocal_WC_0                          ?@0
      0011 putobject_INT2FIX_1_
      0012 opt_plus                               <calldata!mid:+, argc:1, ARGS_SIMPLE>
      0014 jump                                   18
      0016 opt_send_without_block                 <calldata!mid:foo, argc:1, FCALL|ARGS_SIMPLE>
      0018 leave
    HEREDOC

    assert_match(expected_disasm, disasm)
  end

  def test_disable_inlining
    reader, writer = IO.pipe
    Process.waitpid fork {
      reader.close
      RubyVM.disable_inlining!

      3.times do
        bar
      end

      disasm = RubyVM::InstructionSequence.disasm(method(:bar))
      writer.write(Marshal.dump(disasm))
    }

    writer.close
    disasm = Marshal.load(reader.read)

    expected_disasm = <<~HEREDOC
      0000 putself                                                          (   6)[LiCa]
      0001 putobject                              9
      0003 opt_send_without_block                 <calldata!mid:foo, argc:1, FCALL|ARGS_SIMPLE>
      0005 leave                                  [Re]
    HEREDOC

    assert_match(expected_disasm, disasm)
  end
end
