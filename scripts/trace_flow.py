#!/usr/bin/env python3
r"""Summarize a GVSoC debug trace as: instruction -> blocks traversed -> cycle.

Generate the trace with:
    gvrun ... run --trace=. --trace-level=debug | sed 's/\x1b\[[0-9;]*m//g' > all.txt

Usage:
    trace_flow.py all.txt [--core /chip/soc/fc] [--elf prog.elf] [--phases]
                          [--csv] [--only-mem] [--limit N] [--cycle SPEC [--match RE]]
"""

import argparse
import bisect
import csv
import subprocess
import re
import sys

LINE_RE = re.compile(r'^\s*(\d+):\s*(\d+):\s*\[(\S+)\s*\]\s*(.*)$')
EXEC_RE = re.compile(r'Executing instruction \(addr: (0x[0-9a-fA-F]+)\)')

# Messages showing that a request reached a block
ACCESS_RE = re.compile(r'IO req|Memory access|access \(|Data request')


def short(path):
    path = re.sub(r'^/chip/(soc/)?', '', path)
    return re.sub(r'/(trace|comp)$', '', path)


def parse(lines, core):
    insn_comp = core + '/insn'
    exec_comp = core + '/exec'
    lsu_comp = core + '/lsu'
    current = None

    for raw in lines:
        m = LINE_RE.match(raw)
        if m is None:
            continue
        _, cycle, comp, msg = m.groups()
        cycle = int(cycle)

        if comp == exec_comp:
            em = EXEC_RE.search(msg)
            if em:
                current = {'pc': em.group(1), 'start': cycle,
                           'fetch': [], 'data': [], 'in_data': False}
            continue

        if current is None:
            continue

        if comp == insn_comp:
            fields = msg.split()
            # "M 1c008214 p.sw a0, a5(a4) a0:... PA:..."
            mnemonic = fields[2] if len(fields) > 2 else ''
            operands = ' '.join(f for f in fields[3:] if ':' not in f and '=' not in f)
            current.update(end=cycle, mnemonic=mnemonic, operands=operands.strip(),
                           mode=fields[0] if fields else '')
            yield current
            current = None
            continue

        if comp == lsu_comp:
            current['in_data'] = True
        elif not ACCESS_RE.search(msg):
            continue

        target = current['data'] if current['in_data'] else current['fetch']
        name = short(comp)
        if not target or target[-1] != name:
            target.append(name)


def load_symbols(elf):
    """Return a sorted list of (addr, name) for the code symbols of an ELF."""
    out = subprocess.check_output(['nm', '-n', elf], text=True)
    syms = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in 'Tt':
            syms.append((int(fields[0], 16), fields[2]))
    return syms


def lookup(syms, addrs, pc):
    idx = bisect.bisect_right(addrs, int(pc, 16)) - 1
    return syms[idx][1] if idx >= 0 else '?'


def print_table(header, rows):
    widths = [max(len(str(r[i])) for r in rows + [header]) for i in range(len(header))]
    fmt = '  '.join('{:<%d}' % w for w in widths)
    print(fmt.format(*header))
    print(fmt.format(*['-' * w for w in widths]))
    for r in rows:
        print(fmt.format(*r))


def print_phases(insns, syms, addrs):
    """Group consecutive instructions by function."""
    rows = []
    for insn in insns:
        func = lookup(syms, addrs, insn['pc'])
        if rows and rows[-1][2] == func:
            rows[-1][1] = insn['start']
            rows[-1][3] += 1
        else:
            rows.append([insn['start'], insn['start'], func, 1])
    print_table(['from', 'to', 'function', 'insns'], rows)


def parse_cycles(spec):
    """'80' -> {80}, '79-80' -> {79, 80}, '415,2197' -> {415, 2197}."""
    cycles = set()
    for part in spec.split(','):
        if '-' in part:
            lo, hi = part.split('-')
            cycles.update(range(int(lo), int(hi) + 1))
        else:
            cycles.add(int(part))
    return cycles


def print_cycles(lines, cycles, match):
    """Print the trace lines of the given cycles, without timestamp and padding."""
    match_re = re.compile(match)
    for raw in lines:
        m = LINE_RE.match(raw)
        if m is None or int(m.group(2)) not in cycles:
            continue
        _, cycle, comp, msg = m.groups()
        if match_re.search(comp):
            print(f'{cycle}: [{comp}] {msg}')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('trace')
    parser.add_argument('--core', default='/chip/soc/fc',
                        help='core component path (default: /chip/soc/fc)')
    parser.add_argument('--csv', action='store_true', help='output CSV instead of a table')
    parser.add_argument('--only-mem', action='store_true',
                        help='only show instructions with a data access')
    parser.add_argument('--limit', type=int, default=0, help='max number of rows')
    parser.add_argument('--elf', default=None, help='ELF file, adds a function column')
    parser.add_argument('--phases', action='store_true',
                        help='summarize execution by function (requires --elf)')
    parser.add_argument('--cycle', default=None,
                        help='print the raw trace lines of these cycles (e.g. 80, 79-80, 415,2197)')
    parser.add_argument('--match', default=r'loader|/fc/|_ico|/l2/|fc_icache|stdout|fll_soc|apb_soc_ctrl',
                        help='with --cycle, only components matching this regex')
    args = parser.parse_args()

    if args.cycle is not None:
        with open(args.trace, errors='replace') as f:
            print_cycles(f, parse_cycles(args.cycle), args.match)
        return

    syms, addrs = [], []
    if args.elf is not None:
        syms = load_symbols(args.elf)
        addrs = [s[0] for s in syms]

    if args.phases:
        if args.elf is None:
            parser.error('--phases requires --elf')
        with open(args.trace, errors='replace') as f:
            print_phases(parse(f, args.core), syms, addrs)
        return

    with open(args.trace, errors='replace') as f:
        rows = []
        prev = None
        for insn in parse(f, args.core):
            # Cycles until the next instruction starts
            if prev is not None:
                prev[1] = insn['start'] - prev[0]
            prev = None
            if args.only_mem and not insn['data']:
                continue
            rows.append([
                insn['start'],
                0,
                insn['pc'],
                lookup(syms, addrs, insn['pc']) if syms else '-',
                f"{insn['mnemonic']} {insn['operands']}".strip(),
                ' -> '.join(insn['fetch']) or '-',
                ' -> '.join(insn['data']) or '-',
            ])
            prev = rows[-1]
            if args.limit and len(rows) >= args.limit:
                break

    header = ['cycle', 'cycles', 'pc', 'function', 'instruction', 'fetch path', 'data path']
    if args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(header)
        w.writerows(rows)
        return

    print_table(header, rows)


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
