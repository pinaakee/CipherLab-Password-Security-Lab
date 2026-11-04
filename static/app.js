const $ = (id) => document.getElementById(id);
const password = $("password");
let selectedAlgorithm = "scrypt";
let latestHash = "";

function setChecks(checks={}) {
  for (const key of ["length","uppercase","lowercase","digit","symbol"]) {
    $("c-"+key).classList.toggle("pass", !!checks[key]);
  }
}
function updateMatrix(hash) {
  const cells = [...$("matrix").children];
  const chars = hash ? hash.slice(0,32) : "—".repeat(32);
  cells.forEach((cell,i) => {
    cell.textContent = chars[i] || "—";
    cell.classList.toggle("lit", !!hash && i < hash.length);
  });
}
function feedback(items) {
  $("feedback").innerHTML = "";
  (items || []).forEach(item => {
    const li = document.createElement("li");
    li.textContent = item;
    $("feedback").appendChild(li);
  });
}
async function post(path, payload) {
  const response = await fetch(path, {
    method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify(payload)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}
let debounce;
password.addEventListener("input", () => {
  clearTimeout(debounce);
  const value = password.value;
  $("lengthValue").textContent = value.length;
  if (!value) {
    $("entropyValue").textContent = "0.0";
    $("strengthValue").textContent = "—";
    setChecks(); feedback(["Waiting for password input..."]);
    $("matrixStatus").textContent = "AWAITING INPUT";
    updateMatrix(""); return;
  }
  $("matrixStatus").textContent = "ANALYZING";
  debounce = setTimeout(async () => {
    try {
      const result = await post("/api/analyze", {password:value});
      $("entropyValue").textContent = result.entropy.toFixed(1);
      $("strengthValue").textContent = result.strength;
      setChecks(result.checks); feedback(result.feedback);
      updateMatrix(result.sha256); $("matrixStatus").textContent = "FINGERPRINT READY";
    } catch (error) { feedback([error.message]); }
  }, 180);
});
$("togglePassword").addEventListener("click", () => {
  const show = password.type === "password";
  password.type = show ? "text" : "password";
  $("togglePassword").textContent = show ? "◎" : "◉";
  $("togglePassword").setAttribute("aria-label", show ? "Hide password" : "Show password");
});
$("clearPassword").addEventListener("click", () => {
  password.value = ""; password.dispatchEvent(new Event("input")); password.focus();
  $("hashOutput").textContent = "Your generated hash will appear here.";
  $("hashType").textContent = "NO HASH GENERATED"; latestHash = "";
});
document.querySelectorAll(".algo").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll(".algo").forEach(b => b.classList.remove("active"));
  button.classList.add("active"); selectedAlgorithm = button.dataset.algo;
  $("algoDescription").textContent = selectedAlgorithm === "scrypt"
    ? "Scrypt is a salted, deliberately expensive password hash designed for password storage."
    : "SHA-256 creates a fast 256-bit digest. Useful for learning; do not use it to store passwords.";
}));
$("hashButton").addEventListener("click", async () => {
  if (!password.value) { $("hashOutput").textContent = "Enter a password first."; return; }
  $("hashButton").disabled = true; $("hashButton").textContent = "GENERATING...";
  try {
    const result = await post("/api/hash", {password:password.value, algorithm:selectedAlgorithm});
    latestHash = result.hash;
    $("hashOutput").textContent = result.hash;
    $("hashType").textContent = result.algorithm.toUpperCase();
    $("hashBits").textContent = result.bits + " BITS";
  } catch(error) { $("hashOutput").textContent = error.message; }
  finally { $("hashButton").disabled = false; $("hashButton").innerHTML = 'GENERATE HASH <span>↗</span>'; }
});
$("copyHash").addEventListener("click", async () => {
  if (!latestHash) return;
  try { await navigator.clipboard.writeText(latestHash); $("copyHash").textContent = "COPIED ✓"; }
  catch { $("copyHash").textContent = "COPY FAILED"; }
  setTimeout(() => $("copyHash").textContent = "COPY ↗", 1400);
});
$("verifyButton").addEventListener("click", async () => {
  const resultEl = $("verifyResult");
  try {
    const result = await post("/api/verify", {password:password.value, hash:$("storedHash").value});
    resultEl.textContent = result.verified ? "✓ Match — password verified." : "✕ No match — password was not verified.";
    resultEl.className = "verify-result " + (result.verified ? "good" : "bad");
  } catch(error) {
    resultEl.textContent = error.message; resultEl.className = "verify-result bad";
  }
});
