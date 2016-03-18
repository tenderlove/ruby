# frozen_string_literal: false
require 'test/unit'
require "-test-/integer"

class TestIntegerExt < Test::Unit::TestCase
  def test_my_integer_to_f
    assert_raise(TypeError) do
      Bug::Integer::MyInteger.new.to_f
    end

    begin
      Bug::Integer::MyInteger.class_eval do
        def to_f
        end
      end

      assert_nothing_raised do
        Bug::Integer::MyInteger.new.to_f
      end
    ensure
      Bug::Integer::MyInteger.class_eval do
        remove_method :to_f
      end
    end
  end
end
