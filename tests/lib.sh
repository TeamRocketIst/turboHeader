#!/usr/bin/env bash

configure_java_home() {
  if [[ -z "${JAVA_HOME:-}" && -x /usr/libexec/java_home ]]; then
    JAVA_HOME="$(/usr/libexec/java_home)"
    export JAVA_HOME
  fi
}

find_native_library() {
  local build_dir="$1"
  local candidate
  for candidate in \
    "$build_dir/libturboheader_il2cpp.so" \
    "$build_dir/libturboheader_il2cpp.dylib" \
    "$build_dir/turboheader_il2cpp.dll" \
    "$build_dir/Release/turboheader_il2cpp.dll"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  printf 'TurboHeader native library not found under %s\n' "$build_dir" >&2
  return 1
}
