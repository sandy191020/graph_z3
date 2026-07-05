"""
Vulnerability triage scanner.

Produces CWE-tagged findings in the style of a security triage report:

    medium_overflow
    -------------------
    CWE-120
    Status: SAT
    Constraint: strlen(input) > 127
    Witness: "A"*180
    Reason: strncpy copies 200 bytes into 128-byte stack buffer.

Three tiers of confidence, and each finding says which it is:

  1. Z3-CONFIRMED  — derived from an actual crash state that the symbolic
     engine reached and solved (see interfaces.py's crash handling). These
     have a real SAT/UNSAT status and a real witness computed by Z3 against
     the binary's actual path constraints. Highest confidence.

  2. STATIC (call-graph) — a user function is confirmed, via the real call
     graph, to call a known-dangerous library function (strcpy, gets,
     sprintf, memcpy, ...). This is a precise structural fact, but whether
     it's actually exploitable (buffer sizes, reachability) isn't verified
     by the solver, so status is "STATIC" rather than SAT/UNSAT.

  3. STATIC (heuristic) — pattern-matched from disassembly (off-by-one loop
     bounds, sign-confusion casts, missing-null-check derefs, leak
     candidates). These are best-effort and can have false positives; they
     exist to point a human at something worth checking, not to replace
     manual review.

  4. Hardcoded credentials are found by scanning printable strings in the
     binary's data sections — reliable, but purely textual (no symbolic
     component).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
import re


@dataclass
class VulnFinding:
    finding_id: str
    function_name: str
    cwe: Optional[str]
    title: str
    status: str          # SAT | UNSAT | STATIC | STATIC (heuristic) | N/A
    constraint: str
    witness: str
    reason: str
    severity: str        # Low | Medium | High | Critical
    address: str = ""
    confidence: str = "heuristic"   # "z3-confirmed" | "static" | "heuristic" | "textual"


# (cwe, title, reason template) — reason templates describe *why* the
# function is dangerous in general; call-site-specific detail (buffer size,
# etc.) usually requires source or deeper analysis than the disassembly
# alone provides, so these stay general-purpose but accurate.
DANGEROUS_FUNCS: Dict[str, Tuple[str, str, str]] = {
    'strcpy':  ('CWE-120', 'Buffer Overflow (strcpy)',
                "strcpy() performs no bounds checking on the destination buffer; if the source "
                "string is longer than the destination's allocated size, adjacent memory is overwritten."),
    'strcat':  ('CWE-120', 'Buffer Overflow (strcat)',
                "strcat() appends without checking the destination's remaining capacity, allowing "
                "an overflow once the combined length exceeds the buffer size."),
    'sprintf': ('CWE-120', 'Buffer Overflow (sprintf)',
                "sprintf() writes a formatted string with no length limit, so attacker-controlled "
                "input can overflow the destination buffer."),
    'gets':    ('CWE-120', 'Buffer Overflow (gets)',
                "gets() reads an unbounded line from stdin directly into a fixed-size buffer with "
                "no length check whatsoever — one of the most reliably exploitable primitives in C."),
    'strncpy': ('CWE-120', 'Buffer Overflow (strncpy)',
                "strncpy() can still overflow if the specified length argument exceeds the "
                "destination buffer's actual allocated size, and won't null-terminate if truncated."),
    'memcpy':  ('CWE-120', 'Buffer Overflow (memcpy)',
                "memcpy() copies exactly the requested number of bytes with no bounds checking "
                "against the destination buffer's size."),
    'scanf':   ('CWE-120', 'Buffer Overflow (scanf)',
                'scanf("%s", ...) reads an unbounded token directly into a fixed-size buffer with '
                "no length limit."),
    'alloca':  ('CWE-789', 'Uncontrolled Memory Allocation (alloca)',
                "alloca() allocates stack memory for a caller-controlled size with no bounds "
                "checking, which can exhaust the stack (stack-clash style crash)."),
}

# Functions whose return value is commonly NULL-on-failure and dangerous to
# dereference unchecked.
NULLABLE_RETURN_FUNCS = {'malloc', 'calloc', 'realloc', 'fopen', 'getenv', 'strstr', 'strchr'}

ALLOCATOR_FUNCS = {'malloc', 'calloc', 'realloc'}
DEALLOCATOR_FUNCS = {'free'}

CRED_KEYWORDS = ('password', 'passwd', 'pass', 'secret', 'api_key', 'apikey',
                  'access_token', 'auth_token', 'private_key', 'db_pass', 'db_user_pass')


def _slugify(name: str) -> str:
    s = re.sub(r'[^a-zA-Z0-9]+', '_', name).strip('_').lower()
    return s or "unnamed"


def compact_witness(byte_values: bytes, constrained_offsets: Set[int]) -> str:
    """
    Formats a concrete byte-vector witness compactly, e.g. '\'A\'*180', by
    filling unconstrained (don't-care) byte offsets with a readable filler
    ('A') instead of the solver's raw default, then run-length-compressing
    repeated segments. Constrained bytes are shown at their real value;
    short runs of mixed/non-repeating constrained bytes (e.g. a 4-byte
    return address) are grouped into a single hex blob rather than emitted
    one byte at a time.
    """
    if not byte_values:
        return '""'

    display = bytearray(byte_values)
    for i in range(len(display)):
        if i not in constrained_offsets:
            display[i] = 0x41  # 'A' — purely for readability of free bytes

    segments: List[str] = []
    buffer = bytearray()

    def flush_buffer():
        if not buffer:
            return
        if all(32 <= b < 127 for b in buffer):
            segments.append(f'"{buffer.decode("ascii")}"')
        else:
            segments.append('\\x' + ''.join(f'{b:02x}' for b in buffer))
        buffer.clear()

    i, n = 0, len(display)
    while i < n:
        j = i
        while j < n and display[j] == display[i]:
            j += 1
        run_len = j - i
        b = display[i]
        if run_len >= 4:
            flush_buffer()
            printable = 32 <= b < 127
            token = f"'{chr(b)}'" if printable else f"0x{b:02x}"
            segments.append(f'{token}*{run_len}')
        else:
            buffer.extend(display[i:j])
        i = j
    flush_buffer()
    return " + ".join(segments) if segments else '""'


def first_meaningful_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip("- ").strip()
        if line and "no constraints" not in line.lower():
            return line
    return "(no path constraint recorded)"


class VulnerabilityScanner:
    """
    Runs a battery of best-effort detectors against a loaded binary.
    `loader` is the project's BinaryLoader (already .analyze()'d).
    """

    def __init__(self, loader):
        self.loader = loader

    def scan_static(self) -> List[VulnFinding]:
        """Runs every detector that doesn't require live symbolic execution."""
        findings: List[VulnFinding] = []
        findings.extend(self._scan_dangerous_calls())
        findings.extend(self._scan_off_by_one_loops())
        findings.extend(self._scan_sign_confusion())
        findings.extend(self._scan_null_deref())
        findings.extend(self._scan_memory_leaks())
        findings.extend(self._scan_hardcoded_credentials())
        return findings

    # ------------------------------------------------------------------
    # 1. Dangerous library calls (structural fact via the real call graph)
    # ------------------------------------------------------------------
    def _scan_dangerous_calls(self) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        try:
            functions = self.loader.get_functions()
            cg = self.loader.get_call_graph()
        except Exception:
            return findings
        if cg is None or functions is None:
            return findings

        for func_addr in list(cg.nodes()):
            try:
                func = functions.function(func_addr)
            except Exception:
                continue
            if not func or func.name not in DANGEROUS_FUNCS:
                continue

            cwe, title, reason = DANGEROUS_FUNCS[func.name]
            try:
                callers = list(cg.predecessors(func_addr))
            except Exception:
                callers = []

            for caller_addr in callers:
                try:
                    caller = functions.function(caller_addr)
                except Exception:
                    continue
                if not caller or getattr(caller, 'is_simprocedure', False) or getattr(caller, 'is_plt', False):
                    continue

                findings.append(VulnFinding(
                    finding_id=f"{_slugify(caller.name)}_{_slugify(func.name)}",
                    function_name=caller.name,
                    cwe=cwe,
                    title=title,
                    status="STATIC",
                    constraint=f"reachable call: '{caller.name}' -> {func.name}()",
                    witness="Not yet symbolically confirmed. If the symbolic execution trace reaches "
                            "and crashes at this call, a concrete witness will appear as a separate "
                            "Z3-confirmed finding above.",
                    reason=reason,
                    severity="High" if cwe == "CWE-120" else "Medium",
                    address=hex(caller.addr),
                    confidence="static",
                ))
        return findings

    # ------------------------------------------------------------------
    # 2. Off-by-one loop bounds (heuristic: `<=`/`jle`/`jbe` against a
    #    small constant inside a loop back-edge)
    # ------------------------------------------------------------------
    def _scan_off_by_one_loops(self) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        try:
            cfg = self.loader.get_cfg()
            functions = self.loader.get_functions()
        except Exception:
            return findings
        if cfg is None:
            return findings

        # Identify loop back-edges: an edge (src -> dst) where dst dominates
        # src in the block-level CFG (dst's address is <= src's, and dst is
        # reachable from itself again — approximated here by dst.addr <= src.addr
        # combined with an existing forward path, which is a cheap, common
        # heuristic for compiler-generated loops).
        try:
            edges = list(cfg.graph.edges())
        except Exception:
            return findings

        seen_funcs: Set[str] = set()
        for src, dst in edges:
            if dst.addr > src.addr:
                continue  # not a back-edge candidate
            try:
                blk = self.loader.project.factory.block(src.addr)
                insns = blk.capstone.insns if blk.capstone else []
            except Exception:
                continue
            if not insns:
                continue

            cmp_insn = None
            for insn in insns:
                if insn.mnemonic.lower() == 'cmp':
                    cmp_insn = insn
            last_mn = insns[-1].mnemonic.lower()
            if cmp_insn is None or last_mn not in ('jle', 'jbe', 'jg', 'jae'):
                continue

            try:
                func = functions.floor_func(src.addr)
                func_name = func.name if func else "Unknown"
            except Exception:
                func_name = "Unknown"

            if func_name in seen_funcs or func_name == "Unknown":
                continue
            seen_funcs.add(func_name)

            op_str = cmp_insn.op_str
            findings.append(VulnFinding(
                finding_id=f"{_slugify(func_name)}_off_by_one",
                function_name=func_name,
                cwe="CWE-193",
                title="Possible Off-By-One Loop Bound",
                status="STATIC (heuristic)",
                constraint=f"loop condition uses inclusive comparison: cmp {op_str} ; {last_mn}",
                witness="Unconfirmed — construct an input that drives the loop counter to the "
                        "boundary value and check whether the (N+1)-th write lands outside the buffer.",
                reason=f"Loop in '{func_name}' uses an inclusive bound ({last_mn.upper()} after 'cmp {op_str}'), "
                       f"a classic off-by-one pattern (e.g. 'for (i = 0; i <= size; i++)') that writes one "
                       f"element past the end of a buffer sized exactly 'size'.",
                severity="Medium",
                address=hex(src.addr),
                confidence="heuristic",
            ))
        return findings

    # ------------------------------------------------------------------
    # 3. Sign confusion (heuristic: negative immediate later feeds an
    #    allocator/copy-size argument in the same function)
    # ------------------------------------------------------------------
    def _scan_sign_confusion(self) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        try:
            functions = self.loader.get_functions()
        except Exception:
            return findings
        if functions is None:
            return findings

        for func in list(functions.values()):
            if getattr(func, 'is_simprocedure', False) or getattr(func, 'is_plt', False):
                continue
            try:
                block_addrs = list(func.block_addrs)
            except Exception:
                continue

            found_negative_mov = False
            calls_allocator = False
            for addr in block_addrs:
                try:
                    blk = self.loader.project.factory.block(addr)
                    insns = blk.capstone.insns if blk.capstone else []
                except Exception:
                    continue
                for insn in insns:
                    mn = insn.mnemonic.lower()
                    if mn == 'mov' and re.search(r',\s*(-1|0xffffffff|0xffffffffffffffff)\b', insn.op_str):
                        found_negative_mov = True
                    if mn == 'call' and any(
                        a in insn.op_str for a in ALLOCATOR_FUNCS.union({'memcpy', 'strncpy'})
                    ):
                        calls_allocator = True

            if found_negative_mov and calls_allocator:
                findings.append(VulnFinding(
                    finding_id=f"{_slugify(func.name)}_sign_confusion",
                    function_name=func.name,
                    cwe="CWE-195",
                    title="Signed/Unsigned Confusion in Size Argument",
                    status="STATIC (heuristic)",
                    constraint="a -1 (0xffffffff...) constant reaches a size-like argument before an "
                               "allocation/copy call",
                    witness='Unconfirmed — supply a negative size value (e.g. via an unchecked int '
                            'input) and check whether it reaches malloc()/memcpy() as SIZE_MAX.',
                    reason=f"'{func.name}' assigns -1 to a register that later reaches an allocation or "
                           f"copy call. When a negative int is implicitly cast to size_t, -1 becomes "
                           f"SIZE_MAX, typically causing a huge allocation request or a wraparound that "
                           f"under-allocates a buffer relative to a subsequent copy.",
                    severity="High",
                    address=hex(func.addr),
                    confidence="heuristic",
                ))
        return findings

    # ------------------------------------------------------------------
    # 4. Null-pointer dereference (heuristic: call to a nullable-return
    #    function with no visible test/cmp on the result before next use)
    # ------------------------------------------------------------------
    def _scan_null_deref(self) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        try:
            functions = self.loader.get_functions()
        except Exception:
            return findings
        if functions is None:
            return findings

        for func in list(functions.values()):
            if getattr(func, 'is_simprocedure', False) or getattr(func, 'is_plt', False):
                continue
            try:
                block_addrs = sorted(func.block_addrs)
            except Exception:
                continue

            flagged = False
            for addr in block_addrs:
                try:
                    blk = self.loader.project.factory.block(addr)
                    insns = blk.capstone.insns if blk.capstone else []
                except Exception:
                    continue

                for idx, insn in enumerate(insns):
                    if insn.mnemonic.lower() != 'call':
                        continue
                    if not any(name in insn.op_str for name in NULLABLE_RETURN_FUNCS):
                        continue
                    # Look at the next few instructions in this block for a
                    # test/cmp against the return register before it's used.
                    checked = False
                    for nxt in insns[idx + 1: idx + 4]:
                        nm = nxt.mnemonic.lower()
                        if nm in ('test', 'cmp'):
                            checked = True
                            break
                        if nm in ('jmp', 'ret'):
                            break
                    if not checked:
                        flagged = True
                        break
                if flagged:
                    break

            if flagged:
                findings.append(VulnFinding(
                    finding_id=f"{_slugify(func.name)}_null_deref",
                    function_name=func.name,
                    cwe="CWE-476",
                    title="Possible Missing NULL Check",
                    status="STATIC (heuristic)",
                    constraint="return value of a nullable-return call used without a preceding test/cmp",
                    witness="Unconfirmed — force the allocator/lookup call to fail (e.g. exhaust memory, "
                            "or supply input that makes strstr()/strchr() return NULL) and observe the "
                            "subsequent dereference.",
                    reason=f"'{func.name}' calls a function that commonly returns NULL on failure "
                           f"(malloc/calloc/fopen/getenv/strstr/strchr), and the disassembly doesn't "
                           f"show a test/cmp on the result before it appears to be used again.",
                    severity="Medium",
                    address=hex(func.addr),
                    confidence="heuristic",
                ))
        return findings

    # ------------------------------------------------------------------
    # 5. Memory leaks (heuristic: function allocates but no free() is
    #    reachable anywhere in its call subtree)
    # ------------------------------------------------------------------
    def _scan_memory_leaks(self) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        try:
            functions = self.loader.get_functions()
            cg = self.loader.get_call_graph()
        except Exception:
            return findings
        if functions is None or cg is None:
            return findings

        # Precompute which functions call free(), directly or transitively,
        # using a simple reachability walk over the call graph.
        free_addrs = {f.addr for f in functions.values() if f.name in DEALLOCATOR_FUNCS}
        reaches_free_cache: Dict[int, bool] = {}

        def reaches_free(addr: int, seen: Optional[Set[int]] = None) -> bool:
            if addr in reaches_free_cache:
                return reaches_free_cache[addr]
            seen = seen or set()
            if addr in seen:
                return False
            seen.add(addr)
            try:
                succs = list(cg.successors(addr))
            except Exception:
                succs = []
            result = any(s in free_addrs or reaches_free(s, seen) for s in succs)
            reaches_free_cache[addr] = result
            return result

        for func in list(functions.values()):
            if getattr(func, 'is_simprocedure', False) or getattr(func, 'is_plt', False):
                continue
            calls_alloc = False
            try:
                for callee_addr in cg.successors(func.addr):
                    callee = functions.function(callee_addr)
                    if callee and callee.name in ALLOCATOR_FUNCS:
                        calls_alloc = True
                        break
            except Exception:
                continue

            if calls_alloc and not reaches_free(func.addr):
                findings.append(VulnFinding(
                    finding_id=f"{_slugify(func.name)}_memory_leak",
                    function_name=func.name,
                    cwe="CWE-401",
                    title="Potential Memory Leak",
                    status="Detected statically",
                    constraint="N/A",
                    witness="Not symbolically solvable (a leak is an absence-of-action bug, not a "
                            "path constraint).",
                    reason=f"'{func.name}' calls an allocator (malloc/calloc/realloc) but no call to "
                           f"free() is reachable from it in the call graph, suggesting the allocated "
                           f"memory is never released on at least one path.",
                    severity="Low",
                    address=hex(func.addr),
                    confidence="heuristic",
                ))
        return findings

    # ------------------------------------------------------------------
    # 6. Hardcoded credentials (textual scan of data sections)
    # ------------------------------------------------------------------
    def _scan_hardcoded_credentials(self) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        try:
            main_obj = self.loader.project.loader.main_object
        except Exception:
            return findings

        try:
            sections = [s for s in main_obj.sections if s.name in ('.data', '.rodata', '.rdata', '.bss') and s.filesize > 0]
        except Exception:
            sections = []

        seen: Set[str] = set()
        for sec in sections:
            try:
                data = self.loader.project.loader.memory.load(sec.vaddr, sec.filesize)
            except Exception:
                continue
            for match in re.finditer(rb'[\x20-\x7e]{4,}', data):
                s = match.group().decode('ascii', errors='ignore')
                low = s.lower()
                if any(k in low for k in CRED_KEYWORDS) and s not in seen:
                    seen.add(s)
                    findings.append(VulnFinding(
                        finding_id=f"hardcoded_credential_{_slugify(s)[:24]}",
                        function_name="(data section)",
                        cwe="CWE-798",
                        title="Hardcoded Credential",
                        status="Detected statically",
                        constraint="N/A",
                        witness=s,
                        reason=f"The string '{s}' matches common credential-related naming and is "
                               f"embedded directly in the binary's {sec.name} section, meaning anyone "
                               f"with the binary can extract it.",
                        severity="Medium",
                        address=hex(sec.vaddr),
                        confidence="textual",
                    ))
        return findings