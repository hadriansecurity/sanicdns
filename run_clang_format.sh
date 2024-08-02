find ./src -iname *.h -o -iname *.cpp | xargs clang-format -i
find ./test -iname *.h -o -iname *.cc | xargs clang-format -i
find ./utils -iname *.h -o -iname *.cc | xargs clang-format -i