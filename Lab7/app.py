# app.py
"""
Streamlit app — Hashing, Code Obfuscation, Safe Decoder, and Execute Pasted Code.
Features:
- Hash functions for strings/files
- Code obfuscation (Base64, zlib+Base64, marshal+Base64, char-code, multilayer)
- Safe decoder/inspector (decodes base64/zlib/marshal without executing)
- Execute the exact pasted code in a separate subprocess (confirmation required)
- Persists last pasted code and last obfuscated text in session_state

WARNING: Running arbitrary code is dangerous. Only run trusted code or run inside an isolated VM/container.
Run with: streamlit run app.py
"""

import streamlit as st
import hashlib
import base64
import zlib
import marshal
import dis
import re
import io
import tempfile
import subprocess
import os
import sys
import platform
import time
from typing import Dict, Callable, Optional, Tuple

# Optional unix resource module
try:
    import resource  # type: ignore
except Exception:
    resource = None

# -------------------------
# Core: HashGenerator
# -------------------------
class HashGenerator:
    def __init__(self):
        self.supported_algorithms: Dict[str, Callable] = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha224": hashlib.sha224,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
        }

    def hash_string(self, text: str, algorithm: str = "sha256") -> str:
        algo = algorithm.lower()
        if algo not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        h = self.supported_algorithms[algo]()
        h.update(text.encode("utf-8"))
        return h.hexdigest()

    def hash_file(self, file_bytes: bytes, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
        algo = algorithm.lower()
        if algo not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        h = self.supported_algorithms[algo]()
        offset = 0
        while chunk := file_bytes[offset: offset + chunk_size]:
            h.update(chunk)
            offset += chunk_size
        return h.hexdigest()


# -------------------------
# Core: CodeObfuscator
# -------------------------
class CodeObfuscator:
    def base64_obfuscation(self, code: str) -> str:
        encoded = base64.b64encode(code.encode()).decode()
        return f"import base64\nexec(base64.b64decode('{encoded}').decode())"

    def zlib_compression_obfuscation(self, code: str) -> str:
        compressed = zlib.compress(code.encode())
        encoded = base64.b64encode(compressed).decode()
        return f"import zlib, base64\nexec(zlib.decompress(base64.b64decode('{encoded}')).decode())"

    def marshal_obfuscation(self, code: str) -> str:
        compiled = compile(code, "<string>", "exec")
        marshaled = marshal.dumps(compiled)
        encoded = base64.b64encode(marshaled).decode()
        return f"import marshal, base64\nexec(marshal.loads(base64.b64decode('{encoded}')))"

    def string_charcode_obfuscation(self, text: str) -> str:
        codes = ",".join(str(ord(c)) for c in text)
        return f"''.join(chr(x) for x in [{codes}])"

    def multilayer_obfuscation(self, code: str) -> str:
        inner = self.zlib_compression_obfuscation(code)
        return self.base64_obfuscation(inner)


# -------------------------
# Safe decoders (do NOT exec recovered code)
# -------------------------
def extract_first_base64_blob(text: str) -> Optional[str]:
    m = re.search(r"['\"]([A-Za-z0-9+/=]{40,})['\"]", text)
    return m.group(1) if m else None


def decode_base64_to_text(blob: str) -> Optional[str]:
    try:
        return base64.b64decode(blob).decode("utf-8")
    except Exception:
        return None


def decode_base64_to_bytes(blob: str) -> Optional[bytes]:
    try:
        return base64.b64decode(blob)
    except Exception:
        return None


def decode_zlib_from_base64(blob: str) -> Optional[str]:
    b = decode_base64_to_bytes(blob)
    if b is None:
        return None
    try:
        return zlib.decompress(b).decode("utf-8")
    except Exception:
        return None


def inspect_marshal_from_base64(blob: str) -> Optional[Tuple[object, str]]:
    b = decode_base64_to_bytes(blob)
    if b is None:
        return None
    try:
        co = marshal.loads(b)
    except Exception:
        return None
    buf = io.StringIO()
    dis.dis(co, file=buf)
    return co, buf.getvalue()


def decode_charcode_expr(expr: str) -> Optional[str]:
    m = re.search(r"\[([0-9,\s]+)\]", expr)
    if not m:
        return None
    try:
        nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
        return "".join(chr(n) for n in nums)
    except Exception:
        return None


def attempt_unwrap(payload_text: str) -> dict:
    """
    Attempt to unwrap common obfuscation layers safely (no exec).
    Returns a dict summarizing findings.
    """
    result = {
        "found_base64_blob": False,
        "base64_text": None,
        "zlib_text": None,
        "marshal_disasm": None,
        "raw_bytes_preview": None,
    }
    blob = extract_first_base64_blob(payload_text)
    if not blob:
        return result
    result["found_base64_blob"] = True
    # try base64 -> text
    txt = decode_base64_to_text(blob)
    if txt is not None:
        result["base64_text"] = txt
        return result
    # try base64 -> zlib -> text
    ztxt = decode_zlib_from_base64(blob)
    if ztxt is not None:
        result["zlib_text"] = ztxt
        return result
    # try base64 -> marshal
    mres = inspect_marshal_from_base64(blob)
    if mres is not None:
        _, disasm = mres
        result["marshal_disasm"] = disasm
        return result
    # fallback raw bytes preview
    raw = decode_base64_to_bytes(blob)
    if raw is not None:
        result["raw_bytes_preview"] = raw[:200]
    return result


# -------------------------
# Cross-platform subprocess executor (Windows-safe)
# -------------------------
def run_code_in_subprocess(source_code: str, timeout_seconds: int = 5) -> Tuple[int, str, str]:
    """
    Cross-platform runner that writes source_code to a temporary file and executes it
    with the same Python interpreter. Avoids flags that cause initialization errors on Windows.
    Returns (exit_code, stdout, stderr).
    """
    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as tmp:
        tmp_path = tmp.name
        tmp.write(source_code)

    cmd = [sys.executable, tmp_path]  # avoid "-u"
    env = {"PATH": os.environ.get("PATH", "")}

    # Windows-specific startupinfo to hide console window (optional)
    startupinfo = None
    creationflags = 0
    if platform.system() == "Windows":
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        except Exception:
            startupinfo = None

    # On Unix, optionally set simple resource limits via preexec_fn
    preexec_fn = None
    if resource is not None and platform.system() != "Windows":
        def _limit():
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (timeout_seconds, timeout_seconds + 1))
            except Exception:
                pass
            try:
                mem = 300 * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            except Exception:
                pass
        preexec_fn = _limit

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            startupinfo=startupinfo,
            creationflags=creationflags,
            preexec_fn=preexec_fn,
        )
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout_seconds)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_bytes, stderr_bytes = proc.communicate()
            exit_code = -1
            stderr_bytes = stderr_bytes + f"\n*** Process killed after timeout ({timeout_seconds}s) ***".encode()
        stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
    except Exception as ex:
        stdout = ""
        stderr = f"Executor error: {ex}"
        exit_code = -2
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    return exit_code, stdout, stderr


# -------------------------
# Streamlit UI: combine everything
# -------------------------
st.set_page_config(page_title="Security Demo: Hash, Obfuscation, Decoder, Executor", layout="wide")
st.title("🔐 Hashing · Obfuscation · Decoder · Execute (DEMO)")

# Initialize session_state entries
if "last_obfuscated" not in st.session_state:
    st.session_state.last_obfuscated = ""
if "last_pasted_code" not in st.session_state:
    st.session_state.last_pasted_code = "print('hello world')\n"

menu = st.sidebar.radio("Section", ["Hash Functions", "Code Obfuscation", "Decoder & Execute"], index=1)

# Instances
hg = HashGenerator()
ob = CodeObfuscator()

# ---------- Hash Functions ----------
if menu == "Hash Functions":
    st.header("🔒 Hash Functions")
    tab1, tab2 = st.tabs(["Interactive Demo", "Avalanche Demo"])

    with tab1:
        st.subheader("Interactive Hashing")
        option = st.selectbox("Choose an operation", ["Hash a string", "Hash a file", "Compare two strings"])
        if option == "Hash a string":
            text = st.text_input("Enter text to hash:", key="hf_text")
            algorithm = st.selectbox("Select algorithm", list(hg.supported_algorithms.keys()), index=3, key="hf_alg")
            if st.button("Generate Hash", key="hf_gen"):
                if text:
                    st.code(hg.hash_string(text, algorithm))
                else:
                    st.warning("Please enter some text.")
        elif option == "Hash a file":
            uploaded_file = st.file_uploader("Choose a file", key="hf_file")
            algorithm = st.selectbox("Select algorithm", list(hg.supported_algorithms.keys()), index=3, key="hf_file_alg")
            if st.button("Generate File Hash", key="hf_file_btn"):
                if uploaded_file is not None:
                    file_bytes = uploaded_file.getvalue()
                    st.code(hg.hash_file(file_bytes, algorithm))
                else:
                    st.warning("Please upload a file.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                text1 = st.text_area("First string:", key="hf_cmp_1")
            with col2:
                text2 = st.text_area("Second string:", key="hf_cmp_2")
            algorithm = st.selectbox("Select algorithm", list(hg.supported_algorithms.keys()), index=3, key="hf_cmp_alg")
            if st.button("Compare Hashes", key="hf_cmp_btn"):
                same = hg.compare_hashes(text1, text2, algorithm)
                if same:
                    st.success("The hashes are identical.")
                else:
                    st.error("The hashes are different.")
                st.write("Hash 1:")
                st.code(hg.hash_string(text1, algorithm))
                st.write("Hash 2:")
                st.code(hg.hash_string(text2, algorithm))

    with tab2:
        st.subheader("Avalanche Effect Demo")
        original = "password"
        modified = "Password"
        st.write(f"Original: `{original}`")
        st.write(f"Modified: `{modified}`")
        st.write("SHA-256 values:")
        st.code(f"{hg.hash_string(original)}\n{hg.hash_string(modified)}")

# ---------- Code Obfuscation ----------
elif menu == "Code Obfuscation":
    st.header("🕵️ Code Obfuscation (demo)")
    st.subheader("Paste Python source to obfuscate and/or run")
    src = st.text_area("Source code (script or function)", height=300, value=st.session_state.last_pasted_code, key="ob_src")
    st.session_state.last_pasted_code = src  # persist pasted code

    method = st.selectbox("Method", ["Base64", "Zlib + Base64", "Marshal + Base64", "Char-code", "Multilayer (zlib then base64)"], key="ob_method")

    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Obfuscate", key="obf_btn"):
            if not src.strip():
                st.warning("Enter source to obfuscate.")
            else:
                if method == "Base64":
                    out = ob.base64_obfuscation(src)
                elif method == "Zlib + Base64":
                    out = ob.zlib_compression_obfuscation(src)
                elif method == "Marshal + Base64":
                    out = ob.marshal_obfuscation(src)
                elif method == "Char-code":
                    out = ob.string_charcode_obfuscation(src)
                else:
                    out = ob.multilayer_obfuscation(src)
                st.subheader("Obfuscated result (preview)")
                st.code(out)
                st.session_state.last_obfuscated = out

    with col2:
        st.subheader("Run pasted code as a normal script (subprocess)")
        st.info("This runs EXACTLY the code you pasted above in a separate Python process. STDOUT/STDERR will be captured and shown.")
        st.checkbox("✅ I understand this will execute code on my machine", key="confirm_execute_obf")
        # Use confirmation checkbox state explicitly
        confirmed = st.session_state.get("confirm_execute_obf", False)
        timeout_seconds = st.number_input("Timeout seconds", min_value=1, max_value=120, value=5, key="exec_timeout_obf")
        if st.button("Run pasted code now", key="run_obf"):
            if not confirmed:
                st.error("Please confirm that you understand this will execute code.")
            elif not src.strip():
                st.error("Paste code above to run.")
            else:
                st.info("Executing pasted code in subprocess...")
                exit_code, stdout, stderr = run_code_in_subprocess(src, timeout_seconds=int(timeout_seconds))
                st.subheader(f"Subprocess exit code: {exit_code}")
                if stdout:
                    st.subheader("STDOUT")
                    st.code(stdout)
                if stderr:
                    st.subheader("STDERR / Errors")
                    st.code(stderr)
                if not stdout and not stderr:
                    st.info("No output captured from subprocess.")

# ---------- Decoder & Execute (Inspector) ----------
else:
    st.header("🛠 Decoder & Inspector (safe: no exec)")

    st.write("Paste obfuscated source and click Analyze. This will attempt to decode base64/zlib/marshal without executing recovered code.")
    payload = st.text_area("Obfuscated text (or paste last generated)", height=300, value=st.session_state.last_obfuscated, key="decoder_payload")

    if st.button("Analyze", key="analyze_btn"):
        if not payload.strip():
            st.warning("Paste something to analyze.")
        else:
            res = attempt_unwrap(payload)
            if not res["found_base64_blob"]:
                st.info("No obvious base64 blob found. Try pasting exact obfuscated text.")
            else:
                if res["base64_text"]:
                    st.subheader("Base64 -> Text (decoded)")
                    st.code(res["base64_text"][:10000])
                elif res["zlib_text"]:
                    st.subheader("Base64 -> zlib -> Text (decoded)")
                    st.code(res["zlib_text"][:10000])
                elif res["marshal_disasm"]:
                    st.subheader("Base64 -> marshal -> Disassembly")
                    st.code(res["marshal_disasm"][:20000])
                elif res["raw_bytes_preview"] is not None:
                    st.subheader("Base64 -> Raw bytes (preview)")
                    st.write(res["raw_bytes_preview"])
                else:
                    st.info("Decoding attempted but produced no readable output.")

    st.markdown("---")
    st.subheader("Char-code expression decoder")
    st.write("This reverses expressions like: `''.join(chr(x) for x in [72,101,108,108,111])`")
    char_expr = st.text_input("Paste char-code expression (or the whole obfuscated text):", key="char_expr")
    if st.button("Decode char-code", key="decode_char"):
        if not char_expr.strip():
            st.warning("Enter an expression with numeric array brackets `[...]`.")
        else:
            out = decode_charcode_expr(char_expr)
            if out is None:
                st.error("No numeric array found or failed to decode.")
            else:
                st.success("Decoded string:")
                st.code(out)

st.markdown("---")
st.caption("Notes: Executor runs code in a subprocess with timeout. This reduces risk but is NOT a full sandbox. For untrusted code use a VM/container.")
