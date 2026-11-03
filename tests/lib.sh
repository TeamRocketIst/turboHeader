#!/usr/bin/env bash

configure_java_home() {
  if [[ -z "${JAVA_HOME:-}" && -x /usr/libexec/java_home ]]; then
    JAVA_HOME="$(/usr/libexec/java_home)"
    export JAVA_HOME
  fi
}

java_classpath() {
  local separator=:
  local windows=false
  local result=""
  local entry
  if [[ "$#" -eq 0 ]]; then
    printf 'Java classpath requires at least one entry\n' >&2
    return 1
  fi
  if command -v cygpath >/dev/null 2>&1; then
    separator=';'
    windows=true
  fi
  for entry in "$@"; do
    if [[ -z "$entry" ]]; then
      printf 'Java classpath entry is empty\n' >&2
      return 1
    fi
    if [[ "$windows" == true ]]; then
      entry="$(cygpath -m -- "$entry")" || return
    fi
    if [[ -z "$entry" || "$entry" == *"$separator"* ]]; then
      printf 'Java classpath entry is empty or contains the path-list separator\n' >&2
      return 1
    fi
    if [[ -n "$result" ]]; then
      result+="$separator"
    fi
    result+="$entry"
  done
  printf '%s\n' "$result"
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
