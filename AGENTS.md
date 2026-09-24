# Ada Script

## 1. Project Overview
**Ada Script** is a framework for reverse engineering that can analyze executable files, emulate runtime behavior, and generate .lst and .asm files.

## 2. Purpose and Features
The primary purpose of this agent framework is to automate complex reverse engineering and analysis workflows. Key features include:


- **Analyzer Agent**: Performs static analysis of executable files
- **Emulator Agent**: Executes binaries in a controlled environment
- **Parser Agent**: Processes and structures analysis results
- **Database**: Stores analysis results

## 4. Installation and Setup

### Prerequisites
- Python 3.10

### Installation Steps
```bash
# Clone the repository
git clone https://github.com/xor2003/ada_script.git
cd ada_script

# Install dependencies
pip install -r requirements.txt

```


## 7. Limitations and Known Issues

### Running Tests
To run the test suite:
```bash
pytest
```

### Testing the Parser with a Complex File
To test the IDC parser with a more complex file:
```bash
python -c "from idc_engine import parse_idc; print(parse_idc('egame.idc', {}))"
```

### Real Processing Workflow
To run the full processing pipeline:
```bash
python ada.py egame.exe -s egame.idc --debug --full --classify --xrefs
```

### Verifying the generated assembly (uasm + alink round-trip)
`egame.asm` must assemble with zero errors and link into a working MZ exe:
```bash
uasm -Zm -c -Fo=/tmp/egame.obj egame.asm      # 0 errors required
/home/xor/kvikdos/alink/alink -m -o /tmp/egame_rebuilt.exe /tmp/egame.obj
```
Assembler-compatibility rules baked into the generator:
- `.286` (not .386+): uasm emits a 67h addr-size prefix on absolute mem
  operands under .386+, shifting code and breaking short jumps.
- No `.model`/DGROUP: an empty DGROUP makes every `seg:` fixup resolve
  against the wrong frame -> alink "offset out of range".  Instead emit
  `assume cs:<seg>` / `assume ds:nothing, ...` per segment and
  `assume reg:<seg>` at each `split_sreg_range` event (sreg_ranges table).
- `fs:`/`gs:` assumes don't exist on .286 - never emit them.
- `align`/`even` fail in use16 segments: emit literal `db N dup(90h)`.
- A branch target that is a data item needs a `name:` line before the `db`
  (a colon label types it as code); a data cell used as an indirect
  call/jmp target must NOT get one (it is a dword/word variable).
- `lcall`/`ljmp` render as `call|jmp dword ptr ds:label`.
- `struc N dup(<0>)` fails on strucs with array members: use `dup(<>)`.
- uasm is case-insensitive: rename symbols colliding with registers,
  mnemonics, directives, or each other (`_asm_renames`).

### Fast re-render (render-only changes)
Full pipeline is minutes; for renderer-only edits re-render straight from
the existing DB (~20s).  See /tmp/rerender.py pattern: open analysis.db
with sqlite3 directly (Database(path) is non-destructive; only
Database(path, fresh=True) drops tables -- mz_parser uses that on a real
parse), rebuild Analyzer state, call render() per insn, UPDATE
op_str/asm_str/db_bytes, then OutputGenerator(...).generate_asm/lst.

### Byte-exact rebuild (uasm -> MS LINK round-trip = 100% image match)
Link with MS LINK 5.60 (byte-packs `byte` segments like the original;
alink para-aligns and has broken seg fixups) e.g. via
`kvikdos LINK.EXE obj,exe,,nul`.  uasm minimizes encodings, so .asm must
defeat that where the original used a longer form:
- `label[reg]` indexed operands force relocatable disp16.  When the
  original used disp8 (`insn.encoding.disp_size==1`), emit numeric
  `[reg+disp]` instead; for disp16==0 with no label, use `db_bytes`.
- uasm shortens imm16->imm8 (`81`->`83`, acc-imm16 `05/0D/../3D`->`83`,
  `68`->`6A`, `69`->`6B`) whenever the imm fits signed int8.  Flag
  `inst['db_bytes']` to emit original bytes (`instructions.db_bytes`).
- Segment override on a string op: `lodsb`->`lodsb byte ptr es:[si]`;
  stos/scas (es-implicit dest) can't express it -> `db_bytes`.
- `xchg r,r`: capstone prints (r/m,reg) but uasm encodes op1->reg field;
  swap operands in asm_str.  With ax involved uasm emits 90+r -> `db_bytes`.
- `name:` inside proc is procedure-local in masm/uasm; emit `name::` so
  cross-proc self-modifying-code refs (`cs:loc_x+7`) resolve.
- struc items emit real initializers `S <'None', 0, ..>` (quoted string for
  >4-byte byte-array members, `{n} dup(0)` for zero arrays); the struc def
  must declare those members `db N dup(?)` -- `dq` stores strings reversed.

### Quality gates
```bash
venv/bin/ruff check .
venv/bin/python -m pytest -x -q
venv/bin/pyright analyzer.py output_generator.py
venv/bin/radon cc analyzer.py output_generator.py -n C -s
venv/bin/lizard analyzer.py output_generator.py -C 15
```

@RTK.md
