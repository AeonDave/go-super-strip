#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_ROOT="$SCRIPT_DIR/logs"
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
RUN_ROOT="$LOG_ROOT/cli_matrix_${TIMESTAMP}"

mkdir -p "$RUN_ROOT"

BIN_PATH="$RUN_ROOT/gosstrip"
PATTERN_FILE="$RUN_ROOT/patterns.txt"
OVERLAY_FILE="$RUN_ROOT/overlay_payload.bin"
REGEX_MARKER="CLI_REGEX_MARKER"
REGEX_INLINE_PRIMARY="CLI_REGEX_INLINE"
REGEX_INLINE_SECONDARY="CLI_REGEX_EXTRA"
SECTION_NAME=".clisec"
SECTION_PAYLOAD="CLI_SECTION_PAYLOAD"
SECTION_PASSWORD="cli-section-pass"
OVERLAY_PASSWORD="cli-overlay-pass"

build_cli() {
  (cd "$REPO_ROOT" && go build -o "$BIN_PATH" .)
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1" >&2
    exit 1
  fi
}

build_pe_fixture() {
  local output="$RUN_ROOT/simple_pe.exe"
  local source="$REPO_ROOT/testfiles/simple.c"
  require_tool x86_64-w64-mingw32-gcc
  x86_64-w64-mingw32-gcc -O2 "$source" -o "$output"
  printf '%s\n' "$output"
}

to_wsl_path() {
  wsl.exe wslpath -a "$1" | tr -d '\r'
}

build_elf_fixture() {
  local output="$RUN_ROOT/simple_elf"
  local source="$REPO_ROOT/testfiles/simple.c"
  if [[ "$(uname -s)" == "Linux" ]]; then
    require_tool gcc
    gcc -O2 "$source" -o "$output"
  elif command -v wsl.exe >/dev/null 2>&1; then
    local src_wsl out_wsl
    src_wsl=$(to_wsl_path "$source")
    out_wsl=$(to_wsl_path "$output")
    wsl.exe bash -lc "gcc -O2 '$src_wsl' -o '$out_wsl'"
  else
    require_tool gcc
    gcc -O2 "$source" -o "$output"
  fi
  chmod +x "$output" 2>/dev/null || true
  printf '%s\n' "$output"
}

prepare_assets() {
  cat <<'EOF' >"$PATTERN_FILE"
# CLI matrix regex patterns
CLI_REGEX_MARKER
EOF
  printf 'CLI_OVERLAY_PAYLOAD' >"$OVERLAY_FILE"
}

log_cmd() {
  local log_file=$1
  shift
  {
    printf '\n[%s] CMD:' "$(date +"%Y-%m-%d %H:%M:%S")"
    for token in "$@"; do
      printf ' %q' "$token"
    done
    printf '\n'
  } >>"$log_file"
  if "$@" >>"$log_file" 2>&1; then
    printf '[%s] OK\n' "$(date +"%H:%M:%S")" >>"$log_file"
  else
    printf '[%s] FAILED\n' "$(date +"%H:%M:%S")" >>"$log_file"
    return 1
  fi
}

run_simple_flow() {
  local target=$1
  local mode=$2
  local fixture=$3
  local work_dir="$RUN_ROOT/${target}_${mode}_simple"
  mkdir -p "$work_dir"
  local work_bin="$work_dir/$(basename "$fixture")"
  cp "$fixture" "$work_bin"
  local log_file="$work_dir/analyze_obfuscate.log"
  local obf_flag="-o"
  if [[ "$mode" == "force" ]]; then
    obf_flag="-o=force=true"
  fi
  log_cmd "$log_file" "$BIN_PATH" "-a=mode=deep" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "$obf_flag" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-a=mode=deep" "$work_bin"
}

run_regex_flow() {
  local target=$1
  local mode=$2
  local fill=$3
  local fixture=$4
  local pattern_file=$5
  local work_dir="$RUN_ROOT/${target}_${mode}_regex_fill-${fill}"
  mkdir -p "$work_dir"
  local work_bin="$work_dir/$(basename "$fixture")"
  cp "$fixture" "$work_bin"
  local log_file="$work_dir/analyze_regex.log"
  printf '%s%s%s' "$REGEX_MARKER" "$REGEX_INLINE_PRIMARY" "$REGEX_INLINE_SECONDARY" >>"$work_bin"
  local file_regex="-r=fill=${fill},pattern=${pattern_file}"
  local inline_regex_primary="-r=fill=${fill},pattern=${REGEX_INLINE_PRIMARY}"
  local inline_regex_secondary="-r=fill=${fill},pattern=${REGEX_INLINE_SECONDARY}"
  log_cmd "$log_file" "$BIN_PATH" "-a=mode=deep" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "$file_regex" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "$inline_regex_primary" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "$inline_regex_secondary" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-a=mode=deep" "$work_bin"
}

run_pipeline_flow() {
  local target=$1
  local mode=$2
  local fill=$3
  local fixture=$4
  local pattern_file=$5
  local overlay_payload=$6
  local work_dir="$RUN_ROOT/${target}_${mode}_pipeline_fill-${fill}"
  mkdir -p "$work_dir"
  local work_bin="$work_dir/$(basename "$fixture")"
  cp "$fixture" "$work_bin"
  local log_file="$work_dir/analyze_strip_compact_obfuscate.log"
  local strip_flag="-s=fill=${fill}"
  local compact_flag="-c"
  local obf_flag="-o"
  local section_name="$SECTION_NAME"
  if [[ "$mode" == "force" ]]; then
    strip_flag="-s=force=true,fill=${fill}"
    compact_flag="-c=force=true"
    obf_flag="-o=force=true"
  fi
  local section_dest="$work_dir/extracted_section.bin"
  local overlay_dest="$work_dir/extracted_overlay.bin"
  log_cmd "$log_file" "$BIN_PATH" "-a=mode=deep" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "$strip_flag" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "$compact_flag" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "$obf_flag" "$work_bin"
  printf '%s' "$REGEX_MARKER" >>"$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-r=pattern=${pattern_file}" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-i=name=${section_name},data=${SECTION_PAYLOAD},password=${SECTION_PASSWORD}" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-l=file=${overlay_payload},password=${OVERLAY_PASSWORD}" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-ei=name=${section_name},password=${SECTION_PASSWORD},destination=${section_dest}" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-el=password=${OVERLAY_PASSWORD},destination=${overlay_dest}" "$work_bin"
  log_cmd "$log_file" "$BIN_PATH" "-a=mode=deep" "$work_bin"
}

main() {
  mkdir -p "$LOG_ROOT"
  build_cli
  prepare_assets

  local pe_fixture elf_fixture
  pe_fixture=$(build_pe_fixture)
  elf_fixture=$(build_elf_fixture)

  for mode in default force; do
    run_simple_flow pe "$mode" "$pe_fixture"
    run_simple_flow elf "$mode" "$elf_fixture"
    for fill in zero random; do
      run_regex_flow pe "$mode" "$fill" "$pe_fixture" "$PATTERN_FILE"
      run_regex_flow elf "$mode" "$fill" "$elf_fixture" "$PATTERN_FILE"
    done
    for fill in zero random; do
      run_pipeline_flow pe "$mode" "$fill" "$pe_fixture" "$PATTERN_FILE" "$OVERLAY_FILE"
      run_pipeline_flow elf "$mode" "$fill" "$elf_fixture" "$PATTERN_FILE" "$OVERLAY_FILE"
    done
  done

  echo "Logs written to: $RUN_ROOT"
}

main "$@"
