# Ace of SPADE (AoS) — Implementation Specification

> Extracted and restructured from "Ace of SPADE: Selective and PArtial DEcryption with Post-Quantum Security" (Sections 3–5, 4.2, and 7). This document is written as an implementation reference: precise I/O signatures, algorithm pseudocode, and protocol message flows. Prose explanation is trimmed to what's needed to implement correctly.
>
> **How to read this doc**: Section 1 gives the minimal math background. Section 2 is the core cryptographic scheme (the part to implement first). Section 3 is the ciphertext-update extension. Section 4 is the multi-party network protocol built on top of Section 2–3. Section 5 gives concrete parameters. Boxes marked `⚠ SOURCE AMBIGUITY` flag places where the original paper's algorithm text is internally inconsistent — read those before implementing the corresponding routine.

---

## 0. What AoS Is

AoS is a **Multi-Client Functional Encryption (MCFE)** scheme with two extra properties:

1. **Selective partial decryption**: a decryption key is bound to a specific target value `v`. Decrypting a ciphertext vector `x = (x_1, ..., x_m)` with that key does **not** reveal `x`; it reveals only a bit vector `y = (y_1, ..., y_m)` where `y_i = 1` iff `x_i == v`, and `y_i = 0` otherwise. This gives qualitative ("does this record equal v?") rather than quantitative (sum/inner-product) analysis on encrypted data.
2. **Ciphertext updatability (CUFE)**: a trusted key curator can issue a token that re-labels an existing ciphertext (`δ_in → δ_out`) without decrypting or re-encrypting it.

The scheme is built from **Ring-LWE (RLWE)**, so it is believed post-quantum secure, unlike its ElGamal-based predecessor SPADE.

---

## 1. Math Background (minimal, needed to implement)

### 1.1 Notation

| Symbol | Meaning |
|---|---|
| `[n]` | `{1, ..., n}` |
| `[x]_q` | `x mod q`, reduced into the symmetric range `(-q/2, q/2]` |
| `y <-$ Y` | `y` sampled uniformly at random from set `Y` |
| `Z_q` | integers in `(-q/2, q/2]` |
| `Z_q[X]` | polynomials over `Z_q` in indeterminate `X` |
| `R_q = Z_q[X] / P(X)` | quotient ring, `P(X)` irreducible over `Z_q[X]` |
| `R_2` | ternary polynomials, coefficients in `{-1, 0, 1}` |
| `D_{q,σ}` | discrete Gaussian distribution over `R_q`, standard deviation `σ` |
| bold lowercase | vectors |
| bold uppercase | matrices |

A cyclotomic ring `R = Z[X]/(X^n + 1)` is used, with `n` a power of 2 (guarantees `X^n + 1` is irreducible).

### 1.2 RLWE Hardness Assumption

**RLWE distribution** — parameters `(n, m, q, X_sk, X_e)`:
Sample secret `sk(x) ~ X_sk`. For each of `m` samples: sample `a(x) <-$ R_q` uniformly, sample error `e(x) ~ X_e`, compute `b(x) = [a(x)·sk(x) + e(x)]_q`, output `(a(x), b(x))`.

- **Search-RLWE**: given `m` samples `(a, b_i = a·sk + e_i)`, recover `sk`.
- **Decisional-RLWE**: distinguish RLWE samples from uniformly random pairs in `R_q × R_q`.

Both are assumed hard for appropriately chosen `(n, q, σ)`. AoS's security reduces to Decisional-RLWE (see §6 summary at the end of this doc).

### 1.3 Base RLWE Public-Key Encryption (building block AoS specializes)

Message space `M = R_t` (plaintext modulus `t`).

```text
RLWE.Setup(1^λ, pp):
    sk <-$ Z_2[X]/(X^n + 1)                  # ternary secret
    a  <-$ R_q
    e0 <- D_{q,σ}
    b  <- [-a * sk + t * e0]_q
    pk <- (b, a)
    return (sk, pk)

RLWE.Enc(pk, x):                             # x in R_t
    (b, a) <- pk
    u <-$ Z_2[X]/(X^n + 1)                   # ternary "encryption randomness"
    e1, e2 <- D_{q,σ}
    c1 <- [b*u + t*e1 + x]_q
    c2 <- [a*u + t*e2]_q
    return c = (c1, c2)

RLWE.Dec(sk, c):
    (c1, c2) <- c
    x* <- [c1 + sk*c2]_q
    x  <- round(x* mod t)                    # recover message by rounding out noise
    return x
```

AoS (§2 below) replaces the plain secret `sk` in decryption with a **function-derived key** `dk_v`, so that decryption only succeeds (yields a clean, near-zero result) when the encrypted value equals the target `v`.

### 1.4 Generic Interfaces AoS Implements

**Multi-Client Functional Encryption (MCFE)** — 4 algorithms:
- `Setup(1^λ, m) -> (sk, pk)` where `sk = (sk_1,...,sk_m)`, `pk = (pk_1,...,pk_m)`
- `Enc(pk_i, x_i, α_i) -> c_i` — encrypt client `i`'s value under client `i`'s private identifier `α_i`
- `KDer(sk_i, f, α_i) -> dk_{α_i,f}` — derive a functional key for function `f` bound to identifier `α_i`
- `Dec(dk_{α_i,f}, c) -> y` — decrypt ciphertext vector `c` to `f(x)`, revealing nothing else

Correctness only holds when all `α_i` used across the ciphertext vector match the `α` the decryption key was derived for (that's what makes it "multi-client": a decryption key for one client's label does not usefully decrypt another's).

**Ciphertext Updatability (CU)** — 2 extra algorithms layered on top of an MCFE scheme:
- `TokGen(sk, δ, δ') -> tk_{δ→δ'}`
- `Upd(tk_{δ→δ'}, c_δ) -> c_δ'`, such that `Dec(dk_{δ',f}, c_δ') == Dec(dk_{δ,f}, c_δ)` w.h.p.

In AoS, the "label" `δ`/`α` and the MCFE "private identifier" are the same object — AoS overloads the private identifier as the update label.

---

## 2. AoS Core Construction (paper §4.1)

### 2.1 Public Parameters

```text
pp = (n, m, q, X_sk, X_e)
```

- `λ`: security parameter, with `q = q(λ)` chosen s.t. `log2(log2(q)) ∈ N*`
- `n`: ring degree (power of 2), `R = Z[X]/(X^n + 1)`
- `m`: number of clients / vector length (max number of data owners / ciphertext-vector slots)
- `X_sk`: uniform distribution over `R_2` (ternary polynomials)
- `X_e = D_{σ,q}`: discrete Gaussian, std. dev `σ = σ(λ)`
- `t = t(λ)`: plaintext modulus, message space `M = R_t = Z_t[X]/(X^n + 1)`
- Ciphertext space: `C = R_q × R_q`

> **Notational convention used below** (from the paper's own remark): during `Setup`, `α` denotes the *list* of all clients' identifiers `(α_1, ..., α_m)`. In `Enc`, `KDer`, `Dec`, `α_i` denotes a *single* client's private identifier. Keep this distinction when implementing — `Setup` produces one `α_i` (and helper key `k_{α_i}`) **per client**, not a single shared value.

### 2.2 Setup

```text
Algorithm 1 — Setup(1^λ, pp)
Input:  security parameter λ, public parameters pp
Output: sk = (sk_1, ..., sk_m), pk = (pk_1, ..., pk_m), helper keys {k_{α_i}}_{i in [m]}

1. a <-$ R_q
   for i in [m]: sk_i <-$ R_2
2. for i in [m]: e_{0,i} <- D_{q,σ}
3. for i in [m]:
       α_i   <-$ R_2                          # this client's private identifier
       e_{α_i} <- D_{q,σ}
       k_{α_i} <- [a * α_i + t * e_{α_i}]_q   # "helper" key tied to α_i
4. for i in [m]:
       b_i <- [-a * sk_i + t * e_{0,i}]_q
       pk_i <- (a, b_i)
5. return (sk = (sk_1,...,sk_m), pk = (pk_1,...,pk_m), {k_{α_i}}_{i in [m]})
```

`a` is shared across all clients; each client `i` gets its own `sk_i`, `pk_i = (a, b_i)`, private identifier `α_i`, and helper key `k_{α_i}`.

> ⚠ **SOURCE AMBIGUITY** — In the paper, step 2/3 write a single shared `e_α <- D_{q,σ}` but then use a per-client `e_{α_i}` inside the helper-key formula `k_{α_i} <- [a·α_i + t·e_{α_i}]_q`. The two notations (`e_α` vs `e_{α_i}`) are not reconciled in the source text. **Recommended resolution** (used above): sample a **fresh** `e_{α_i}` per client `i`, since each client needs its own helper key and reusing one Gaussian sample across all `k_{α_i}` would leak structure between clients' helper keys. Implement with per-client fresh noise.

### 2.3 Encryption

```text
Algorithm 2 — Enc(pk_i, x, α_i)
Input:  client i's public key pk_i = (a, b_i), plaintext x in R_t, private identifier α_i
Output: ciphertext c_x = (c1, c2)

1. u <-$ R_2
   e1, e2 <- D_{q,σ}
2. c1 <- [b_i * α_i + t * e1 + u * x]_q       # carries the message payload
   c2 <- [a * α_i + t * e2 - u]_q             # decryption helper term
3. return c_x = (c1, c2)
```

Note the fresh randomness `u` is sampled per encryption and embedded in both `c1` (multiplying `x`) and `c2`.

### 2.4 Key Derivation

```text
Algorithm 3 — KDer(sk_i, k_{α_i}, v)
Input:  client i's secret key sk_i, i's helper key k_{α_i}, target value v (nonzero, v in R_t)
Output: functional decryption key dk_{α_i,v}

1. for j in [m]:
       e3_j <- D_{q,σ}
       k_j  <- [k_{α_j} * (sk_j - v) + t * e3_j]_q
2. dk_{α_i,v} <- (k_1, ..., k_m)
3. return dk_{α_i,v}
```

The output key has `m` components — one per ciphertext-vector slot — mirroring how `Dec` consumes it (§2.5).

> ⚠ **SOURCE AMBIGUITY** — The original Algorithm 3 pseudocode literally reads:
> ```
> Input: sk_i, k_{α_i}, v
> for j in [m]: k_j <- k_{α_i} * (sk_i - v) + t*e3
> ```
> i.e. it takes a *single* client's `sk_i` and helper key `k_{α_i}` as input, but then loops `j in [m]` recomputing the *same* expression `m` times with a *single* noise sample `e3` reused for every `j`. That would make all `m` components of `dk_{α_i,v}` identical, which is inconsistent with `Dec` (Algorithm 4), which parses a **different** ciphertext `c_{x_i}` and a **different** key component `k_i = dk[i]` for each `i in [m]` (implying the components must differ per slot, tracking each client's own `sk_j`).
>
> **Recommended resolution** (used above): the loop should range over the `m` secret-key components `sk_j` (one per data-owner/vector slot), using **fresh** noise `e3_j` each iteration, and multiplying by the **same** requester identifier's helper key `k_{α_i}` throughout (since the whole point is that this key belongs to the *requesting client i* and is used against ciphertexts from potentially other slots `j`, all sharing that identifier in the multi-client setting where `α_1 = ... = α_m` for correctness — see the MCFE correctness clause in §1.4). If your deployment only ever needs single-slot decryption (`m=1`), this ambiguity is moot. For `m>1`, implement per-slot key components with independent noise as shown above, and test against the correctness identity in §2.6 before shipping.

### 2.5 Decryption

```text
Algorithm 4 — Dec(dk_{α,v}, c_x)
Input:  decryption key dk_{α,v} = (k_1,...,k_m), ciphertext vector c_x = (c_{x_1}, ..., c_{x_m})
Output: y = (y_1, ..., y_m), y_i in {0, 1}

1. for i in [m]:
       (c1, c2) <- c_{x_i}
       k_i <- dk_{α,v}[i]
       y*_i <- [c1 + k_i + v * c2]_q
       y*_i <- reduce(y*_i, into [0, t))        # reduce mod t into [0, t)
       y_i_signed <- reduce(y*_i, into (-q/2, q/2])
2. for i in [m]:
       if y_i_signed == 0: y_i <- 1              # x_i == v
       else:                y_i <- 0              # x_i != v
3. return y = (y_1, ..., y_m)
```

This computes `f_v(x_1,...,x_n) = (1[x_1==v], ..., 1[x_n==v])` — the equality-test / selective partial decryption function.

> ⚠ **SOURCE AMBIGUITY** — Step 3 of the original Algorithm 4 literally writes `y*_i <- c1 + dk_i + v*c2`, using `dk_i` where step 2 just defined `k_i <- dk_{α,v}[i]`. This is almost certainly a typesetting slip for `k_i` (used above); `dk_i` is not otherwise defined. Implement using `k_i` (the per-slot key component from §2.4).

### 2.6 Correctness Identity & Parameter Selection

For a ciphertext `c_{x_i} <- Enc(pk_i, x_i, α)` and `dk_{α,v} <- KDer(sk, k_α, v)`:

```text
y*_i = c1 + k_i + v*c2 = (x_i - v)*u + t*E
```

where the accumulated noise is:

```text
E = e_{0,i}*α + e1 + e_α*(sk_i - v) + e3 + v*e2
```

- If `x_i == v`, the `(x_i - v)*u` term vanishes and `y*_i` reduces to a small multiple of `t*E`, which decodes to `0` after reduction ⇒ output `1` (match).
- If `x_i != v`, `(x_i - v)*u` is a nonzero "large" term (since `u` is ternary/uniform), so `y*_i` does **not** reduce to `0` ⇒ output `0` (no match).

**Correctness requires**: `‖y*_i‖ < q/2`.

**Parameter selection rule** (per Mono et al., BGV-style noise analysis): choose parameters such that

```text
sqrt(n * V_{y*_i}) < q/2
```

where `V_{y*_i}` is the variance of `y*_i` in the "match" case (`u*(x_i - v) = 0`):

```text
V_{y*_i} = V_{t*E} = t^2 * V_{e_{0,i}*α + e1 + e_α*(sk_i - v) + e3 + v*e2}
         = t^2 * σ^2 * (4n/3 + 2 + t^2/6)
```

**Implementation check**: before deploying any parameter set, verify

```text
t^2 * σ^2 * (4n/3 + 2 + t^2/6) < q / 2
```

Use this inequality as a unit test against your chosen `(n, q, σ, t)`.

---

## 3. Ciphertext Updatability Extension (paper §4.2)

Adds two algorithms on top of §2. Token generation is run **only by the trusted key curator (KC)**, who holds `sk`/`pk`.

### 3.1 Token Generation

```text
Algorithm 5 — TokGen(sk, δ_in, δ_out)
Input:  secret key sk (or pk, see note below), two labels δ_in, δ_out
Output: update token tk_{δ_in -> δ_out}

1. e_tk <-$ D^2_{q,σ}                          # a pair of Gaussian samples, one per ciphertext component
2. tk_{δ_in -> δ_out} <- pk * (δ_out - δ_in) + t * e_tk
3. return tk_{δ_in -> δ_out}
```

> Note: the header says the input is `sk`, but the formula uses `pk`; this is consistent with the correctness proof in the paper (which expands the token using `b` and `a`, i.e. public-key material). In practice, since only KC runs `TokGen` and KC holds both, this doesn't affect correctness — implement using `pk = (a, b)`, computing `tk = (b*(δ_out - δ_in) + t*e_tk_1, a*(δ_out - δ_in) + t*e_tk_2)` component-wise, matching the structure of a ciphertext.

### 3.2 Update

```text
Algorithm 6 — Upd(tk_{δ_in -> δ_out}, c_{δ_in})
Input:  update token tk_{δ_in -> δ_out}, ciphertext c_{δ_in} = (c1, c2)
Output: c_{δ_out}, an encryption of the same plaintext under label δ_out

1. c_{δ_out} <- tk_{δ_in -> δ_out} + c_{δ_in}       # component-wise addition
2. return c_{δ_out}
```

No re-encryption or knowledge of the plaintext is needed — the update is a pure ciphertext-space operation.

### 3.3 Correctness

```text
c_{δ_out} = tk_{δ_in->δ_out} + c_{δ_in}
          = ( b*δ_out + (e1 + e_tk,1) + u*x ,  a*δ_out + (e2 + e_tk,2) + u )
```

which is distributed as a valid `Enc(pk, x, δ_out)` output as long as `(e1 + e_tk,1)` and `(e2 + e_tk,2)` remain valid (small-enough) RLWE errors — true for any reasonable Gaussian parameter choice. Consequently:

```text
Dec(dk_{f,δ_out}, c_{δ_out}) == Dec(dk_{f,δ_in}, c_{δ_in})
```

**Implementation note**: since `δ` here plays the role of the private identifier `α` from §2, updating a ciphertext's label is literally re-keying which client identifier it's encrypted under — this is why AoS can fold "labels" (MCFE sense) and "identifiers" (per-client sense) into one mechanism.

---

## 4. Real-World Protocol (paper §5)

A concrete deployment protocol wrapping the AoS primitives. All messages are signed and timestamped; every recipient checks **freshness** (timestamp) and **integrity** (signature) before acting.

### 4.1 Entities

| Entity | Role |
|---|---|
| **Key Curator (KC)** | Trusted authority. Runs `Setup`, holds `sk`/`pk`, issues functional decryption keys on request, stores uploaded ciphertexts, can generate update tokens. |
| **Data Owners** `DO = (d_1, ..., d_m)` | Each `d_j` owns a private identifier `α_j`, registers with KC, encrypts and uploads its own data. Owner set is **unbounded** — new owners can register dynamically. |
| **Users** `U = (u_1, ..., u_ℓ)` | Request functional decryption keys from KC (for a value `v` against a specific owner's data), then fetch ciphertexts and run partial decryption locally. |

### 4.2 Threat Model

- **KC is trusted**: holds the master secret key, can decrypt everything; assumed to issue only correctly-scoped decryption keys to requesting users.
- **Data owners are not required to trust each other**: security of one owner's data holds even if all other owners are malicious. Owners are assumed to encrypt honestly (correct plaintexts).
- **Users are untrusted beyond what they can derive** from the ciphertexts + keys KC legitimately gives them.
- **No collusion among users** is assumed (standard assumption for individually-credentialed access-control systems).
- A network-level active adversary can tamper with/inject/replay any of the messages `m_j, m_1..m_6` below (this is what the paper's robustness/secure-access proofs cover) — hence every message is signed and timestamped.

### 4.3 Message Format Convention

Every protocol message has the shape:

```text
⟨ timestamp, payload, signature_over( H(timestamp || payload) ) ⟩
```

Signatures are produced with a standard EUF-CMA-secure signature scheme (any conventional scheme, e.g. Ed25519, is sufficient — the paper's security proof is generic over "a EUF-CMA secure signature scheme 𝔖"). `H` is a hash function (modeled as a random oracle in the security proofs). A generic-purpose IND-CPA-secure PKE scheme (separate from the AoS/RLWE machinery) is used to encrypt small payloads (identifiers, keys) point-to-point.

### 4.4 Protocol Steps

#### Step 1 — System Setup & Data Owner Registration

```text
KC:      (sk, pk) <- AoS.Setup(1^λ, pp)

d_j:     generate private identifier α_j
         c_{α_j}  <- PKE.Enc(pk_KC, j || α_j)          # encrypt identifier for KC
         m_j <- ( t_j, c_{α_j}, Sign(sk_{d_j}, H(t_j || c_{α_j})) )
         send m_j to KC

KC:      verify freshness(t_j) and signature(m_j)
         if valid: store (j, α_j); decrypt c_{α_j} to learn α_j
         m_1 <- ( t_1, pk, Sign(sk_KC, H(t_1 || pk)) )
         send m_1 to d_j (and to any newly-joining owner)

d_j:     verify freshness(t_1) and signature(m_1)
         store pk
```

Registration is **dynamic**: a new owner `d_{m+1}` can join at any later time by running the same `m_j` / `m_1` exchange — the owner set is not fixed at setup time.

#### Step 2 — User Registration (requesting decryption keys)

```text
u_k:     reg <- { (j, v), ... }                         # set of (owner, target-value) pairs
         m_2 <- ( t_2, reg, Sign(sk_{u_k}, H(t_2 || reg)) )
         send m_2 to KC

KC:      verify freshness(t_2) and signature(m_2)
         for each (j, v) in reg:
             dk_{j,v} <- AoS.KDer(sk, v, α_j)             # §2.4
         c_dk <- PKE.Enc(pk_{u_k}, { dk_{j,v} : (j,v) in reg })
         m_3 <- ( t_3, c_dk, Sign(sk_KC, H(t_3 || c_dk)) )
         send m_3 to u_k

u_k:     verify freshness(t_3) and signature(m_3)
         c_dk_plain <- PKE.Dec(sk_{u_k}, c_dk)
         store { dk_{j,v} } locally
```

#### Step 3 — Data Owner Encryption & Upload

```text
d_j:     c_{j,x} <- AoS.Enc(pk, x, α_j)                  # §2.3, x is d_j's plaintext data
         m_4 <- ( t_4, c_{j,x}, Sign(sk_{d_j}, H(t_4 || c_{j,x})) )
         send m_4 to KC

KC:      verify freshness(t_4) and signature(m_4)
         if valid: store c_{j,x}
```

#### Step 4 — Data Access & Local Decryption

```text
u_k:     req <- (idx, event)                             # e.g. "owner d_j", or a time-range filter
         m_5 <- ( t_5, req, Sign(sk_{u_k}, H(t_5 || req)) )
         send m_5 to KC

KC:      verify freshness(t_5) and signature(m_5)
         { c_{j,x} } <- lookup matching stored ciphertexts for req
         m_6 <- ( t_6, { c_{j,x} }, Sign(sk_KC, H(t_6 || { c_{j,x} })) )
         send m_6 to u_k

u_k:     verify freshness(t_6) and signature(m_6)
         y <- AoS.Dec(dk_{j,v}, c_{j,x})                  # §2.5, run locally
         # y_i == 1 means the i-th slot of owner j's data equals v
```

#### Step 5 — Ciphertext Update (optional, any time)

```text
KC:      tk_{δ->δ'} <- AoS.TokGen(sk, δ, δ')              # §3.1
         c_{δ'} <- AoS.Upd(tk_{δ->δ'}, c_δ)                # §3.2
         replace stored ciphertext c_δ with c_{δ'}
```

- Only KC can run this (it's the only entity holding `sk`).
- No additional trust assumption is introduced beyond "KC is trusted," since KC already has plaintext access to everything.
- **Deployment warning from the paper**: if an adversary corrupts KC *and* at least one data owner, they can re-label any ciphertext to that corrupted owner's identifier and thereby gain access to any user's data. Ciphertext updatability should therefore only be exposed in deployments where KC compromise is already catastrophic (which is the paper's stated threat model) — do not add ciphertext-update capability to a lower-trust KC variant without re-analyzing this attack.

### 4.5 End-to-End Sequence Summary

```text
d_j ──m_j (register identifier)──▶ KC ──m_1 (pk)──▶ d_j
u_k ──m_2 (key request: {(j,v)})──▶ KC ──m_3 (enc. dk_{j,v})──▶ u_k
d_j ──m_4 (upload c_{j,x})──▶ KC  [stored]
u_k ──m_5 (data request)──▶ KC ──m_6 (matching ciphertexts)──▶ u_k
u_k: locally runs Dec(dk_{j,v}, c_{j,x}) → y   (no further network round-trip)

KC (any time): TokGen + Upd to re-label a stored ciphertext in place
```

---

## 5. Recommended Parameters (paper §7, Table 1)

Plaintext modulus `t = 2^16` is fixed across all sets.

| Param set | `m` (vector length) | `log2(N)` (ring degree) | `log2(q)` (ciphertext modulus) | `log2(t)` |
|---|---|---|---|---|
| Small (S)  | 100  | 12 | 39 | 16 |
| Medium (M) | 200  | 13 | 42 | 16 |
| Large (L)  | 500  | 14 | 43 | 16 |
| XLarge (XL)| 1000 | 15 | 47 | 16 |

Always re-verify the noise inequality from §2.6 —

```text
t^2 * σ^2 * (4n/3 + 2 + t^2/6) < q / 2
```

— against your actual chosen `σ` before trusting a parameter set; the table gives `(n, q, t)` but `σ` must be picked to satisfy this bound (the source paper references the parameter-selection methodology of Mono et al., "Finding and evaluating parameters for BGV").

### Reference Performance (paper §7.1, Table 2 — single-threaded, Intel i5-1235U @ 4.4GHz, Go + Lattigo library)

| Param set | Setup (ms) | Enc (ms) | KDer (ms) | Dec (ms) | TokGen (ms) | Upd (ms) |
|---|---|---|---|---|---|---|
| S  | 22.43   | 0.49 | 4.88   | 3.59   | 0.47 | 0.024 |
| M  | 74.43   | 1.03 | 7.16   | 9.36   | 0.91 | 0.041 |
| L  | 372.76  | 1.16 | 39.77  | 46.12  | 1.14 | 0.056 |
| XL | 1485.69 | 3.60 | 123.76 | 150.09 | 2.11 | 0.150 |

Going from S → XL (10× more slots, larger ring, larger modulus): ~25× slower runtime, ~43× more memory on average. Use this to sanity-check your own implementation's performance envelope.

---

## 6. Security Properties (summary, for correctness validation — not full proofs)

Your implementation should preserve these three guarantees; use them as design invariants / test properties rather than re-deriving the proofs:

1. **IND-FE-CPA** (semantic security of the core scheme): reduces to Decisional-RLWE. Practical implication: a decryption key `dk_v` for value `v` must reveal nothing about ciphertexts encrypting `x ≠ v` beyond the single bit "not equal." Never reuse randomness `u` across encryptions, never leak `sk_i`/`e0/e1/e2/e3` intermediates.
2. **Robustness**: assuming the signature scheme is EUF-CMA secure, any authorized user can always correctly recover the partial decryption of legitimately-uploaded data, and no adversary can forge a data entry KC will accept. Practical implication: KC must reject any `m_4`/upload whose signature doesn't verify, and must never accept a second upload claiming the same content under a different signer.
3. **Secure Access**: assuming the PKE, the signature scheme, and AoS's IND-FE-CPA all hold, an adversary controlling any set of *uncorrupted* users learns nothing about a data owner's plaintext beyond the equality bits their legitimately-issued keys entitle them to. Practical implication: KC must never issue `dk_{j,v}` to a user who didn't request it, and per-user decryption-key ciphertexts (`m_3`/`c_dk`) must use fresh PKE randomness per user.

---

## 7. Implementation Checklist

- [ ] `Setup(λ, pp) -> (sk, pk, {k_αi})` — §2.2, resolve the `e_α` vs `e_{α_i}` ambiguity (fresh noise per client, recommended)
- [ ] `Enc(pk_i, x, α_i) -> (c1, c2)` — §2.3
- [ ] `KDer(sk, k_α, v) -> dk_{α,v}` (m components) — §2.4, resolve the per-slot indexing ambiguity
- [ ] `Dec(dk_{α,v}, c_x) -> y ∈ {0,1}^m` — §2.5, use `k_i` not the undefined `dk_i`
- [ ] Unit test: correctness identity + noise bound from §2.6 for every parameter set you support
- [ ] `TokGen(pk, δ_in, δ_out) -> tk` — §3.1
- [ ] `Upd(tk, c_δin) -> c_δout` — §3.2
- [ ] Generic EUF-CMA signature scheme + IND-CPA PKE scheme for the transport layer (§4.3) — not specified by the paper, choose standard primitives (e.g. Ed25519 + X25519/ML-KEM if you want the transport layer to also be post-quantum)
- [ ] KC-side message handlers for `m_j, m_2, m_4, m_5` with freshness + signature checks (§4.4)
- [ ] KC-side storage: `(j, α_j)` registry, ciphertext store keyed by owner/label, per-user key issuance log
- [ ] Dynamic owner registration (owner set is unbounded/open at runtime)
- [ ] Gate ciphertext-update capability behind the same trust boundary as KC itself (see warning in §4.4 Step 5)

---

*Source: "Ace of SPADE: Selective and PArtial DEcryption with Post-Quantum Security" (anonymous submission, 2026). Sections referenced: §3 (Background), §4.1–4.2 (Core Construction & Updatability), §5 (Protocol), §6 (security summary only), §7 (parameters/benchmarks).*
