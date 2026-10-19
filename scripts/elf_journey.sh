#!/usr/bin/env bash
# Run an ELF on a GVSoC target with full traces and dump its journey through
# the chip: ELF layout, loading into memory, execution phases per function and
# the blocks traversed by each instruction. On pulp-open, it also renders the
# architecture diagram restricted to the blocks used, with the paths highlighted.
#
# Usage: elf_journey.sh <elf> [out_dir] [target] [core]
#   out_dir  default: journey_<elf name>
#   target   default: pulp-open
#   core     default: /chip/soc/fc

set -e

if [ $# -lt 1 ]; then
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

ELF=$(readlink -f "$1")
OUT=${2:-journey_$(basename "$1")}
TARGET=${3:-pulp-open}
CORE=${4:-/chip/soc/fc}
SCRIPTS=$(dirname "$(readlink -f "$0")")

source "$SCRIPTS/../sourceme.sh"
mkdir -p "$OUT"
OUT=$(readlink -f "$OUT")

echo "[1/7] ELF layout"
{
    echo "=== Header ==="
    readelf -hW "$ELF" | grep -E 'Machine|Entry'
    echo
    echo "=== Segments (what gets loaded, and where) ==="
    readelf -lW "$ELF" | sed -n '/Program Headers/,/^$/p'
    echo "=== Sections ==="
    readelf -SW "$ELF" | sed -n '/Section Headers/,/Key to Flags/p' | grep -v -E '\.debug_|Key to'
    echo
    echo "=== Functions ==="
    nm -n "$ELF" | grep -E ' [Tt] '
} > "$OUT/01_elf_layout.txt"
riscv64-unknown-elf-objdump -d "$ELF" > "$OUT/01_elf_disasm.txt" 2>/dev/null || \
    llvm-objdump -d "$ELF" > "$OUT/01_elf_disasm.txt"

echo "[2/7] Running GVSoC ($TARGET) with full traces"
gvrun --target "$TARGET" --work-dir "$OUT/work" \
    --param chip/soc/binary="$ELF" \
    image flash run --trace=. --trace-level=debug \
    | sed 's/\x1b\[[0-9;]*m//g' > "$OUT/02_trace_all.txt"

# The FC instruction cache only traces its requests at the "trace" level, which
# is too verbose for the full trace above, so get it from a second, focused run.
echo "[3/7] Running GVSoC again for the fetch path (instruction cache)"
gvrun --target "$TARGET" --work-dir "$OUT/work" \
    --param chip/soc/binary="$ELF" \
    image flash run --trace=fc_icache --trace=fc_fetch_ico --trace-level=trace \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'Received (IO )?req' > "$OUT/02_trace_fetch.txt" || true

echo "[4/7] Loading of the ELF into the chip"
{
    echo "# Each ELF segment is written by the loader through the interconnect into memory."
    echo "# Then the loader sets the core boot address and enables fetch."
    echo
    awk '
        /loader\/trace.*Starting section/ { on = 1 }
        on && /loader\/trace|axi_ico\/trace|soc_ico\/[a-z_]+\/trace|\/l2\/[a-z0-9_]+\/trace/ && !/Forwarding interleaved|shared_[0-9]+_cut_/ { print }
        on && /loader\/trace.*Sending start/ { exit }
    ' "$OUT/02_trace_all.txt"
} > "$OUT/03_load.txt"

echo "[5/7] Execution phases per function"
python3 "$SCRIPTS/trace_flow.py" "$OUT/02_trace_all.txt" --core "$CORE" --elf "$ELF" --phases \
    > "$OUT/04_phases.txt"

echo "[6/7] Instruction -> blocks -> cycle"
python3 "$SCRIPTS/trace_flow.py" "$OUT/02_trace_all.txt" --core "$CORE" --elf "$ELF" \
    > "$OUT/05_flow.txt"
python3 "$SCRIPTS/trace_flow.py" "$OUT/02_trace_all.txt" --core "$CORE" --elf "$ELF" --csv \
    > "$OUT/05_flow.csv"

echo "[7/7] Architecture diagram"
if [ "$TARGET" = pulp-open ]; then
    (cd "$OUT" && gvrun --target "$TARGET" --work-dir "$OUT/work" diagram > /dev/null)
    KEEP=loader,axi_ico,fc,fc_icache,fc_fetch_ico,fc_data_ico,ll_ico,hb_ico,priv0,priv1
    KEEP=$KEEP,l_shared,shared_cut,apb_ico,stdout,soc_eu,fll_soc,fll_periph,fll_cluster,fc_itc,timer,apb_soc_ctrl
    python3 "$SCRIPTS/arch_view.py" "$OUT/architecture.dot" "$OUT/06_arch.png" --keep "$KEEP" \
        --title "pulp-open: blocks used by $(basename "$ELF")" --dpi 110
    python3 "$SCRIPTS/arch_view.py" "$OUT/architecture.dot" "$OUT/06_arch_paths.png" --keep "$KEEP" \
        --title "purple = ELF loading, blue = fetch, green = L2 data, orange = APB peripherals" --dpi 110 \
        --path "#7b1fa2:loader,axi_ico,ll_ico" --path "#7b1fa2:loader,fc" \
        --path "#1565c0:fc,fc_icache,fc_fetch_ico,ll_ico,priv1" \
        --path "#2e7d32:fc,fc_data_ico,ll_ico,priv0" --path "#2e7d32:fc_data_ico,hb_ico,l_shared,shared_cut" \
        --path "#e65100:ll_ico,apb_ico,stdout" --path "#e65100:apb_ico,soc_eu" \
        --path "#e65100:apb_ico,fll_soc" --path "#e65100:apb_ico,fll_periph" --path "#e65100:apb_ico,fll_cluster" \
        --path "#e65100:apb_ico,fc_itc" --path "#e65100:apb_ico,timer" --path "#e65100:apb_ico,apb_soc_ctrl"
else
    echo "  skipped: block list is only defined for pulp-open"
fi

echo
echo "Program output:"
grep -v -E '^\s*-?[0-9]+: -?[0-9]+: \[' "$OUT/02_trace_all.txt" | sed 's/^/  /' || true
echo
echo "Results in $OUT:"
ls -1 "$OUT" | sed 's/^/  /'
