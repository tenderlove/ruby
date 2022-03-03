class A
  def foo
    self.class
  end
end

def bar(a)
  a.foo
end

a = A.new
p bar(a)
bar(a)

puts RubyVM::InstructionSequence.disasm(method(:bar))
p bar(a)
