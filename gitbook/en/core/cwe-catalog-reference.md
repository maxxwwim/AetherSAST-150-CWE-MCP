# CWE & Rule Catalog Reference

Complete reference of all **247 security and governance rules** shipped in `aether-engine` v2.6.0: **223 native detectors** (across 52 categories and 84 distinct `CWE-NNN` IDs, including 28 `AETHER-*` novel rules — 88 distinct `CWE-NNN` IDs total with the Community Bundle) plus **24 embedded Semgrep OWASP/CWE rules**.

## Summary Matrix by Module & Domain

| Section | Source Module | Rules | Severity Breakdown | Target Languages / Files |
|---|---|---:|---|---|
| 1. Rust, Network, L1 & Concurrency | `linter.rs` (`L79–L249`, `L516–L560`) | **24** | 15 `CRITICAL`, 9 `HIGH` | `.rs` |
| 2. Web3, Smart Contracts & DeFi | `linter.rs` (`L253–L512`) + `rules.rs` | **35** | 29 `CRITICAL`, 6 `HIGH` | `.sol`, `.rs`, `.yul` |
| 3. SAST Multi-Lang, Architecture, DOM & C/C++ | `linter.rs` (`L563–L1001`) | **48** | 27 `CRITICAL`, 18 `HIGH`, 1 `MEDIUM`, 2 `WARNING` | Polyglot, `.py`, `.js`/`.ts`, `.c`/`.cpp`/`.h`, `README.md` contracts |
| 4. Deep Systems, ZK-SNARKs & Injection | `deep_rules.rs` | **27** | 21 `CRITICAL`, 6 `HIGH` | `.rs`, `.sol`, `.circom`, `.py`, `.js`/`.ts` |
| 5. PHP 8.x & Web Security | `php_rules.rs` | **26** | 10 `CRITICAL`, 16 `HIGH` | `.php`, `.phtml`, `.php3`–`.php7`, `.phps` |
| 6. Zig Systems & C-ABI | `zig_rules.rs` | **15** | 6 `CRITICAL`, 9 `HIGH` | `.zig` |
| 7. C# / .NET / ASP.NET Core | `csharp_rules.rs` | **20** | 7 `CRITICAL`, 10 `HIGH`, 3 `MEDIUM` | `.cs` |
| 8. Novel `AETHER-*` Zero-Day & Backdoors | `epic_novel_rules.rs` | **28** | 19 `CRITICAL`, 9 `HIGH` | Polyglot, `.rs` (incl. `build.rs`), `.php*` |
| **Native Subtotal** | `SecurityLinter::get_supported_cve_rules()` | **223** | **134 `CRITICAL`, 83 `HIGH`, 4 `MEDIUM`, 2 `WARNING`** | All supported languages |
| 9. Semgrep Community Bundle | `community_owasp_cwe.yaml` | **24** | 17 `CRITICAL`, 7 `HIGH` (post-import mapping) | `.py`, `.js`/`.ts`, `.rs`, `.php`, `.go`, `.c`/`.cpp`, `.cs`, `.zig`, `.java` |
| **Grand Total** | Native + Community Bundle | **247** | **151 `CRITICAL`, 90 `HIGH`, 4 `MEDIUM`, 2 `WARNING`** | Full polyglot coverage |

{% hint style="warning" %}
**Reconciliation with Legacy Repository Documentation:** Several static Markdown files in the repository lag behind the v2.6.0 Rust source code:
- `crates/security-linter/README.md` displays `v2.5.1` and claims `222` native / `246` total rules.
- `CWE_CATALOG.md` claims `222 + 24 = 246` rules, lists only **220** unique rule IDs (omitting `RULE_FORBIDDEN_FUNCTION`, `RULE_FORBIDDEN_EXTENSION`, and `RULE_MAX_FILES` from `linter.rs:744-770`), and mislabels `RULE_MAX_LINES` as `MEDIUM` instead of **`WARNING`** (`CONTRACT / ARCH-BUDGET-EXCEEDED`).
- `cwe/README.md` claims `222 + 24 = 246` rules and lists only **178** unique rule IDs (omitting all 28 `AETHER-*` rules, 4 `CVE-L1-*` rules, `CVE-WEB3-MERKLE-SECOND-PREIMAGE-LEAF-NODE-COLLISION`, the 3 folder-contract rules, 4 `CVE-INJ-*` rules, `CVE-PHP-STREAM-WRAPPER-PHAR-FILTER`, and 4 `deep_rules.rs` rules).
This page documents the **exact 247 rules** verified in `crates/security-linter/src/` and `rules/community_owasp_cwe.yaml`.
{% endhint %}

## 1. Rust, Network, L1 Blockchain & Concurrency (24 Rules)

Defined in `crates/security-linter/src/linter.rs` (`L79–L249` and `L516–L560`).

| Rule ID | CWE / Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-RUST-DESER-BOMB-OOM` | `CWE-789 / LENGTH-PREFIX-OOM-BOMB` | `CRITICAL` | `.rs`: `bincode::deserialize`, `rmp_serde`, or `Vec::with_capacity` on wire length without `.with_limit()` / `MAX_FRAME_SIZE`. | Enforce `bincode::DefaultOptions::new().with_limit(MAX)` and validate length prefixes before allocating. |
| `CVE-RUST-CANCEL-SAFETY-LOSS` | `CWE-662 / TOKIO-SELECT-CANCEL-LOSS` | `HIGH` | `.rs`: `read_exact`, `write_all`, `read_to_end`, or `read_line` inside `tokio::select!` without `Framed::new`. | Use cancellation-safe `Framed` codecs or move stream I/O into a dedicated task behind an `mpsc` channel. |
| `CVE-RUST-TIMING-SIDECHANNEL` | `CWE-208 / TIMING-SIDE-CHANNEL` | `HIGH` | `.rs`: `==` / `!=` comparison on HMAC, secret, nonce, or signature variables. | Replace `==`/`!=` with `subtle::ConstantTimeEq::ct_eq()`. |
| `CVE-NET-SLOWLORIS-KEEPALIVE-DOS` | `CWE-400 / SLOWLORIS-SOCKET-EXHAUSTION` | `HIGH` | `.rs`: `accept_async`, `TcpListener::accept`, `axum::serve`, or `acquire_many_owned` without `TimeoutLayer` or `tokio::time::timeout`. | Wrap handshakes in `tokio::time::timeout` and attach `tower_http::timeout::TimeoutLayer`. |
| `CVE-NET-SSRF-DNS-REBIND` | `CWE-918 / SSRF-DNS-REBINDING` | `CRITICAL` | `.rs`: Outbound `reqwest` or `TcpStream::connect` to dynamic URL without `is_loopback`/`is_private` checks and redirect blocking. | Resolve DNS, block loopback/private/link-local (`169.254.169.254`) IPs, and set `redirect::Policy::none()`. |
| `CVE-RUST-BLOCKING-IN-ASYNC` | `CWE-400 / ASYNC-EXECUTOR-STARVATION` | `CRITICAL` | `.rs`: Synchronous `std::fs`, `std::thread::sleep`, or `std::net` inside `async fn` without `tokio::task::spawn_blocking`. | Use `tokio::fs`, `tokio::time::sleep`, `tokio::net`, or offload via `spawn_blocking`. |
| `CVE-RUST-INTEGER-OVERFLOW-CAST` | `CWE-190 / AS-CAST-INTEGER-TRUNCATION` | `HIGH` | `.rs`: Unchecked narrowing casts (`as u32`, `as u16`, `as u8`) on sizes, balances, or 64-bit integers. | Replace `as` with `try_into()` or `checked_*` arithmetic. |
| `CVE-RUST-TRANSMUTE-SIZE-MISMATCH` | `CWE-843 / UNSAFE-TRANSMUTE-TYPE-CONFUSION` | `CRITICAL` | `.rs`: `std::mem::transmute` without `bytemuck` or a `// SAFETY:` justification (`[-6..+4]` lines). | Use `bytemuck::cast` / `try_cast` or safe conversions (`from_le_bytes`), or document invariants with `// SAFETY:`. |
| `CVE-RUST-FORGOTTEN-MEM-LEAK` | `CWE-775 / MEM-FORGET-RESOURCE-LEAK-DEADLOCK` | `HIGH` | `.rs`: `std::mem::forget()` called on synchronization guards (`MutexGuard`, `RwLock`) or sockets. | Use `ManuallyDrop` with explicit lifecycle management or let RAII drop guards normally. |
| `CVE-RUST-UNCHECKED-INDEX-SLICING` | `CWE-125 / UNCHECKED-SLICE-INDEX-PANIC-DOS` | `HIGH` | `.rs`: Direct `[offset..offset+len]` slicing on raw network buffers. | Replace direct indexing with `.get(offset..offset + len).ok_or(...)?`. |
| `CVE-RUST-THREAD-POISON-IGNORED` | `CWE-391 / SWALLOWED-MUTEX-POISON-INVARIANT` | `HIGH` | `.rs`: `.unwrap_or_else(\|e\| e.into_inner())` swallowing `Mutex` `PoisonError`. | Propagate poison errors cleanly or rebuild invariant state before recovering the guard. |
| `CVE-RUST-FFI-UNCHECKED-NULL-PTR` | `CWE-476 / FFI-UNCHECKED-NULL-PTR-DEREF` | `CRITICAL` | `.rs`: Raw `*const T` / `*mut T` dereference in `unsafe` without `.is_null()` or `NonNull`. | Check `if ptr.is_null()` or accept `std::ptr::NonNull<T>` across FFI boundaries. |
| `CVE-RUST-PIN-STRUCTURAL-UNPIN-SOUNDNESS-UB` | `RUST-INTERNALS-CRITICAL / PIN-GET-UNCHECKED-MUT-SOUNDNESS-BREAK` | `CRITICAL` | `.rs`: Manual `Pin::get_unchecked_mut` or `Pin::new_unchecked` without `pin_project!`. | Use `pin_project_lite::pin_project!` or `pin-project` instead of manual pin projections. |
| `CVE-L1-BORSH-UNBOUNDED-DESER-OOM` | `L1-P2P-CONSENSUS-CRITICAL / BORSH-ZSTD-WIRE-ALLOCATION-BOMB` | `CRITICAL` | `.rs`: Unbounded `BorshDeserialize::try_from_slice` or `zstd::decode_all` on P2P frames or `ChunkStateWitness`. | Verify peer signatures first and enforce strict max decoded byte limits (`take(MAX_BYTES)`). |
| `CVE-L1-RUNTIME-GAS-PREPAY-BYPASS` | `L1-FEE-BYPASS-CRITICAL / HOST-FN-ALLOCATION-BEFORE-GAS-BURN` | `CRITICAL` | `.rs`: Wasm host function allocating (`vec![0; len]`, `read_memory`) or reading trie state before `burn_gas` / `pay_gas`. | Charge proportional gas (`gas_counter.pay_gas`) before performing memory allocation or host I/O. |
| `CVE-L1-BALANCE-STORAGE-STAKING-DESYNC` | `L1-FUNDS-CRITICAL / BALANCE-MUTATION-WITHOUT-STORAGE-STAKE-CHECK` | `CRITICAL` | `.rs`: Direct `set_amount`, `set_locked`, or `saturating_sub` on account `Balance` without `check_storage_stake`. | Use checked balance helpers (`checked_sub` / `safe_add_balance`) and assert `check_storage_stake` at commit. |
| `CVE-L1-CONSENSUS-UNVERIFIED-WITNESS-CHUNK` | `L1-CONSENSUS-CRITICAL / STATELESS-WITNESS-UNVERIFIED-ENDORSEMENT` | `CRITICAL` | `.rs`: Processing or caching `ChunkStateWitness`, `PartialEncodedChunk`, or `Approval` before validator signature verification. | Verify block/chunk producer cryptographic signatures prior to state mutation or caching. |
| `CVE-L1-CROSS-SHARD-RECEIPT-NONCE-REPLAY` | `L1-TX-CRITICAL / DELEGATE-ACTION-ACCESS-KEY-NONCE-BYPASS` | `CRITICAL` | `.rs`: Executing `DelegateAction` or `SignedTransaction` without `max_block_height`, `FunctionCallPermission`, and atomic `access_key.nonce` update. | Enforce block-height expiration, permission scope, and atomic nonce increment before emitting `ActionReceipt`. |
| `CVE-L1-CRYPTO-BLIND-SCALAR-MERKLE-MALLEABILITY` | `L1-CRYPTO-CRITICAL / UNCHECKED-CURVE-DECOMPRESS-TORSION-SPLIT` | `CRITICAL` | `.rs`: `from_bytes_unchecked` / `decompress_unchecked` on BLS12-381, Ed25519, or BN254 points without subgroup/torsion check. | Reject non-canonical points and verify `is_torsion_free()` / prime-order subgroup membership. |
| `CVE-RUST-ASYNC-MUTEX` | `CWE-667 / ASYNC-DEADLOCK` | `CRITICAL` | `.rs`: Holding `std::sync::Mutex` guard across `.await`. | Switch to `tokio::sync::Mutex` or drop the `std::sync::MutexGuard` before `.await`. |
| `CVE-RUST-UNBOUNDED-CHANNEL` | `CWE-400 / UNBOUNDED-MEMORY-DOS` | `HIGH` | `.rs`: `unbounded_channel()` on WebSocket or network packet pipelines. | Replace with bounded `tokio::sync::mpsc::channel(CAPACITY)` and apply backpressure. |
| `CVE-MMO-UNCHECKED-SPEEDHACK` | `CWE-20 / UNCHECKED-SPEEDHACK` | `HIGH` | `.rs`: Assigning player coordinates directly from client packets without server `delta_t` velocity bounds. | Validate movement deltas against server tick elapsed time and max speed invariants. |
| `CVE-MATH-UNCHECKED-BALANCE` | `CWE-190 / INTEGER-UNDERFLOW` | `CRITICAL` | `.rs`: Decrementing balances or currency without `checked_sub` or `saturating_sub`. | Use `checked_sub(...).ok_or(InsufficientFunds)?` for all currency arithmetic. |
| `CVE-MMO-IDOR-TRUSTED-USERID` | `CWE-639 / IDOR-CLIENT-USERID-SPOOF` | `CRITICAL` | `.rs`: Reading `userId` / `user_id` directly from client payload without server session token resolution. | Derive the acting user ID strictly from the authenticated server-side session or JWT claims. |

## 2. Web3, Smart Contracts & DeFi (35 Rules)

Defined in `crates/security-linter/src/linter.rs` (`L253–L512`, 29 rules) and `crates/security-linter/src/rules.rs` (`AdvancedDefiRules`, 6 rules).

| Rule ID | CWE / Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-WEB3-REENTRANCY-UNCHECKED` | `CWE-841 / REENTRANCY` | `CRITICAL` | `.sol`/`.rs`: Asset transfer or balance update without `ReentrancyGuard` or Checks-Effects-Interactions. | Update state before external calls and apply `nonReentrant`. |
| `CVE-WEB3-SIG-MALLEABILITY` | `CWE-347 / ECDSA-MALLEABILITY` | `CRITICAL` | `.sol`/`.rs`: Signature verification without upper-bound `s < secp256k1_n / 2` check. | Use OpenZeppelin `ECDSA.recover` (v4.7+/v5) or explicitly enforce low-`s` canonical signatures. |
| `CVE-WEB3-UNVALIDATED-CHAINID` | `CWE-294 / CROSS-CHAIN-REPLAY` | `CRITICAL` | `.sol`/`.rs`: EIP-191/712 signature domain missing `chain_id` or `verifyingContract` check. | Include `block.chainid` and `address(this)` in the EIP-712 `DOMAIN_SEPARATOR`. |
| `CVE-WEB3-NONCE-RACE` | `CWE-362 / TOCTOU-NONCE` | `HIGH` | `.sol`/`.rs`: Consuming or deleting the nonce after performing the privileged action. | Increment/invalidate the nonce before executing external logic. |
| `CVE-WEB3-AUTH-BYPASS-MOCK` | `CWE-287 / CRYPTO-SIGNATURE-BYPASS` | `CRITICAL` | `.sol`/`.rs`: Mock signatures (`0xmock`, `bypass_sig`) or `ecrecover` without `signer != address(0)` check. | Reject `address(0)` from `ecrecover` and remove any mock/bypass branches in production code. |
| `CVE-WEB3-ORACLE-SPOT-MANIPULATION` | `CWE-682 / FLASH-LOAN-ORACLE-MANIPULATION` | `CRITICAL` | `.sol`: Spot AMM reserve pricing (`getReserves`, `slot0`, `balanceOf`) without TWAP or Chainlink feed. | Use manipulation-resistant Chainlink feeds or sufficiently long Uniswap v3 TWAPs. |
| `CVE-WEB3-TX-ORIGIN-PHISHING` | `CWE-302 / TX-ORIGIN-AUTHORIZATION-BYPASS` | `CRITICAL` | `.sol`: Authorization check using `tx.origin` instead of `msg.sender`. | Replace `tx.origin` authorization with `msg.sender`. |
| `CVE-WEB3-UNCHECKED-TRANSFER-RETURN` | `CWE-252 / SILENT-TRANSFER-FAILURE-USDT` | `CRITICAL` | `.sol`: Raw ERC-20 `transfer()` / `transferFrom()` without `SafeERC20`. | Use `SafeERC20.safeTransfer` and `safeTransferFrom`. |
| `CVE-WEB3-PERMIT-FRONT-RUNNING` | `CWE-362 / MEMPOOL-SIGNATURE-GRIEFING` | `HIGH` | `.sol`: `token.permit(...)` inside a deposit flow without `try/catch`. | Wrap `permit()` in `try/catch` so mempool front-running does not DoS legitimate deposits. |
| `CVE-WEB3-HOOK-REENTRANCY` | `CWE-841 / ERC777-ERC1363-HOOK-REENTRANCY` | `CRITICAL` | `.sol`: Token transfers without `ReentrancyGuard`, exposing `tokensReceived` ERC-777/1363 hooks. | Protect state-mutating functions with `nonReentrant` even on token-only transfers. |
| `CVE-VM-ACCOUNT-MISSING-OWNER` | `CWE-284 / VM-ACCOUNT-OWNER-CONFUSION` | `CRITICAL` | `.rs`: Account-model VM accepting `AccountInfo` without checking `account.owner == program_id`. | Validate `account.owner == program_id` or use typed `Account<'info, T>` wrappers. |
| `CVE-WEB3-READONLY-REENTRANCY` | `CWE-841 / READONLY-REENTRANCY-LP-ORACLE` | `CRITICAL` | `.sol`: Reading Curve/Balancer `virtual_price` or pool reserves in `view` context without reentrancy lock check. | Check the pool's reentrancy status or enforce `nonReentrant` before pricing LP collateral. |
| `CVE-WEB3-DIRTY-MEMORY-ASSEMBLY` | `CWE-682 / CWE-119-DIRTY-BITS-ASSEMBLY` | `CRITICAL` | `.sol`/`.yul`: Inline assembly (`mload`/`mstore`) handling `< 32`-byte types (`bool`, `address`, `uint8`) without bitmasking. | Mask upper dirty bits (e.g., `and(val, 0xff)`) in Yul/inline assembly. |
| `CVE-WEB3-ERC4626-INFLATION-ATTACK` | `CWE-682 / ERC4626-FIRST-DEPOSITOR-DONATION` | `CRITICAL` | `.sol`: ERC-4626 vault share math lacking virtual shares/assets (`_decimalsOffset()`). | Inherit OpenZeppelin v5 ERC4626 with `_decimalsOffset()` or mint dead shares on initialization. |
| `CVE-WEB3-VAULT-ROUNDING-DIRECTION` | `CWE-682 / INCORRECT-CONVERSION-ROUNDING` | `CRITICAL` | `.sol`: `convertToShares`, `convertToAssets`, or `preview*` using raw `/` or wrong `Rounding` direction. | Always round against the user (favor protocol solvency) via `Math.mulDiv` with explicit `Rounding.Floor`/`Ceil`. |
| `CVE-WEB3-STALE-ORACLE-HEARTBEAT` | `CWE-682 / STALE-ORACLE-ROUND-DATA` | `HIGH` | `.sol`: `latestRoundData()` without `updatedAt == 0`, heartbeat age, and `answeredInRound >= roundId` checks. | Assert `answer > 0`, `updatedAt != 0`, `block.timestamp - updatedAt <= HEARTBEAT`, and `answeredInRound >= roundId`. |
| `CVE-WEB3-UNPROTECTED-CALLBACK-SELECTOR` | `CWE-284 / UNPROTECTED-FLASHLOAN-CALLBACK` | `CRITICAL` | `.sol`: Public/external `onFlashLoan` or `uniswapV3SwapCallback` without `msg.sender` pool check. | Enforce `require(msg.sender == authorizedPool)` and validate callback initiator data. |
| `CVE-WEB3-SIGNATURE-DEADLINE-MISSING` | `CWE-613 / MISSING-SIGNATURE-DEADLINE` | `HIGH` | `.sol`: `ecrecover` / `ECDSA.recover` without `require(block.timestamp <= deadline)`. | Bind a signed `deadline` parameter and revert if `block.timestamp > deadline`. |
| `CVE-WEB3-HOOK-DEFERRED-CHECKS-DESYNC` | `CWE-841 / TRANSIENT-LIQUIDITY-INVARIANT-VIOLATION` | `CRITICAL` | `.sol`: EVC `HookTarget` performing transfers/reads without `!evc.isChecksDeferred()` / `areChecksInProgress()`. | Verify EVC check state (`!evc.isChecksDeferred(account)`) inside vault hooks. |
| `CVE-WEB3-DECIMAL-SCALING-TRUNCATION` | `CWE-682 / ORACLE-DECIMAL-SCALING-UNDERFLOW` | `HIGH` | `.sol`: Hardcoded `10**(18 - decimals)` scaling assuming 18-decimal tokens (breaks 6/8/`>18` decimals). | Dynamically normalize scaling up or down depending on `token.decimals()` vs `18`. |
| `CVE-WEB3-FORK-REWARD-STAKING-DILUTION` | `CWE-682 / REWARD-HARVEST-BEFORE-UPDATE` | `CRITICAL` | `.sol`: Reward distribution or harvest without updating `accRewardPerShare` and `lastRewardBlock` first. | Call `updatePool()` / accrue reward state before modifying user stake or transferring rewards. |
| `CVE-WEB3-EIP1153-TRANSIENT-COMPOSABILITY-LEAK` | `EVM-CANCUN-CRITICAL / TSTORE-UNCLEARED-COMPOSABILITY-POLLUTION` | `CRITICAL` | `.sol`: EIP-1153 `tstore` / `transient` storage written without explicit reset before call completion. | Zero transient slots on exit or scope transient state to single non-reentrant call frames. |
| `CVE-WEB3-EIP7702-EOA-CODE-BYPASS-COLLISION` | `EVM-PECTRA-CRITICAL / EIP7702-EXTCODESIZE-BYPASS-AND-SLOT-COLLISION` | `CRITICAL` | `.sol`: Anti-contract `extcodesize == 0` / `code.length == 0` checks or EIP-7702 delegation lacking ERC-7201 namespaced storage. | Remove `extcodesize == 0` assumptions and use ERC-7201 storage namespaces for EOA delegation contracts. |
| `CVE-WEB3-ERC4337-PAYMASTER-GAS-SIPHON` | `AA-ERC4337-CRITICAL / PAYMASTER-POSTOP-UNBOUNDED-GAS-GRIEFING` | `CRITICAL` | `.sol`: `validatePaymasterUserOp` missing `maxCost`/`postOpGasLimit` caps or deferring ERC-20 `transferFrom` only to `postOp`. | Pre-escrow ERC-20 fees in `validatePaymasterUserOp` and enforce strict `postOpGasLimit` bounds. |
| `CVE-WEB3-OMNICHAIN-LZ-CHANNEL-BRICKING` | `OMNICHAIN-CRITICAL / CROSS-CHAIN-UNCAUGHT-REVERT-FUND-BURN` | `CRITICAL` | `.sol`: `_lzReceive` / `lzReceive` / `_ccipReceive` executing external calls without `try/catch` quarantine (`failedMessages`). | Wrap message execution in `try/catch` and store failed payloads for retry rather than bricking the channel. |
| `CVE-WEB3-EIP150-63-64-GAS-STIPEND-GRIEFING` | `EVM-INTERNALS-CRITICAL / EIP150-63-64TH-SUBCALL-OOG-SILENT-BYPASS` | `CRITICAL` | `.sol`: External `.call` / `try/catch` followed by marking a nonce or message executed without verifying sufficient `gasleft()`. | Assert `gasleft() >= requiredGas` (or use SafeExec) so relayers cannot force inner OOG and keep 1/64 gas. |
| `CVE-WEB3-ZK-SNARK-FIELD-OVERFLOW-ALIASING` | `ZK-CRYPTO-CRITICAL / BN254-SCALAR-FIELD-MODULO-ALIASING` | `CRITICAL` | `.sol`: Groth16/Plonk verifier accepting `uint256` public inputs/nullifiers without `< SNARK_SCALAR_FIELD`. | Enforce `require(input < SNARK_SCALAR_FIELD)` for every public signal and nullifier. |
| `CVE-WEB3-MERKLE-SECOND-PREIMAGE-LEAF-NODE-COLLISION` | `CRYPTO-CRITICAL / MERKLE-64BYTE-LEAF-INTERNAL-NODE-SPOOF` | `CRITICAL` | `.sol`: 64-byte Merkle leaf hashed once with `keccak256(abi.encode(addr, amount))` without double-hash or `0x00` domain prefix. | Double-hash leaves (`keccak256(bytes.concat(keccak256(abi.encode(...))))`) or prepend distinct domain tags. |
| `CVE-WEB3-CREATE2-METAMORPHIC-REINIT-RUG` | `EVM-BYTECODE-CRITICAL / CREATE2-UNSALTED-SENDER-FRONT-RUN-AND-METAMORPHIC` | `CRITICAL` | `.sol`: `CREATE2` using user salt without `keccak256(abi.encode(msg.sender, salt))` or loading dynamic `initCode`. | Derive `CREATE2` salt with `msg.sender` and deploy immutable deterministic bytecode. |
| `DEFI-ASYMMETRIC-ROUNDING` | `CWE-682 / ASYMMETRIC_ROUNDING_RISK` | `HIGH` | `rules.rs` (`.sol`/`.rs`): Raw `/` inside vault conversion functions or economy fee math without `mulDivUp`/`mulDivDown`/`.max(1)`. | Use `Math.mulDiv` directional rounding in Solidity or `.checked_div(...).map(\|v\| v.max(1))` in Rust. |
| `DEFI-STALE-CACHE-AFTER-CALL` | `CWE-362 / STALE_CACHE_TOCTOU` | `CRITICAL` | `rules.rs` (`.sol`/`.rs`): Reusing `VaultCache`, `snapshot`, or `local_balance` fields after `.call`/`.invoke`/`.await` without reloading. | Refresh the cached state immediately after every external call or hook invocation. |
| `EVC-HOOK-BYPASS` | `CWE-841 / EVC_HOOK_BYPASS_RISK` | `CRITICAL` | `rules.rs` (`.sol`): `checkVaultStatus`, `onVaultCall`, `hookTarget`, `preOperationHook`, `postOperationHook` lacking `nonReentrant` / EVC checks. | Add `nonReentrant` and assert `!evc.isChecksDeferred(account) \|\| evc.areChecksInProgress()`. |
| `DEFI-ORACLE-MIN-MAX-CIRCUIT-BREAKER` | `LOGIC-CRITICAL / ORACLE_MIN_MAX_CIRCUIT_BREAKER` | `CRITICAL` | `rules.rs` (`.sol`): Chainlink `latestRoundData()` without checking `minAnswer`/`maxAnswer` bounds or fallback circuit breaker. | Validate `answer > minAnswer && answer < maxAnswer` against the aggregator bounds and fail over safely. |
| `DEFI-ORACLE-L2-SEQUENCER-RACE` | `LOGIC-CRITICAL / L2_SEQUENCER_ORACLE_RACE` | `CRITICAL` | `rules.rs` (`.sol`): L2 (Arbitrum/Optimism/Base) `latestRoundData()` without `sequencerUptimeFeed` + `GRACE_PERIOD_TIME`. | Query the L2 sequencer uptime feed and enforce a post-restart grace period before pricing. |
| `DEFI-TWAP-SHORT-WINDOW` | `LOGIC-CRITICAL / TWAP_SHORT_WINDOW` | `CRITICAL` | `rules.rs` (`.sol`): Uniswap v3/AMM TWAP window `< 1800` seconds (30 minutes) or unbounded setter. | Enforce `twapWindow >= 1800` seconds to raise multi-block MEV manipulation costs. |

## 3. SAST Multi-Language, Architecture Contracts, Front-End & C/C++ (48 Rules)

Defined in `crates/security-linter/src/linter.rs` (`L563–L1001`).

### 3A. SAST & Python Security (17 Rules)

| Rule ID | CWE / Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `SAST_RAW_SQL_INJECTION` | `CWE-89 / SQL-INJECTION` | `CRITICAL` | Polyglot: Dynamic SQL concatenation (`${`, `format!(`, `+`, `%s`, `f"`) with SQL verbs (`SELECT`, `INSERT`, `UPDATE`, `DELETE`). | Use parameterized queries (`sqlx::query!`, prepared statements, or bind parameters). |
| `SAST_HARDCODED_SECRET` | `CWE-798 / HARDCODED-SECRET` | `CRITICAL` | Polyglot: `BEGIN PRIVATE KEY`, `AKIA...`, or plaintext `secret`/`api_key`/`private_key` string assignments. | Load credentials from environment variables or a secret manager; never commit secrets. |
| `CVE-DB-REDIS-UNAUTH-KEYS-DOS` | `CWE-306 / CWE-400-REDIS-KEYS-DOS` | `CRITICAL` | Polyglot: Blocking `O(N)` Redis `KEYS *` command or unauthenticated RESP/TCP cache server. | Replace `KEYS` with cursor-based `SCAN` and enforce Redis `AUTH` / ACLs. |
| `CVE-RUST-UNSAFE-MEM` | `CWE-119 / CVE-RUST-UNSAFE-MEM` | `CRITICAL` | `.rs`: `unsafe` blocks or raw `*mut T` without `// SAFETY:` annotation (`[-6..+4]` lines). | Prefer safe Rust abstractions or document soundness invariants with `// SAFETY:`. |
| `CVE-RUST-PANIC-DOS` | `CWE-248 / CVE-RUST-PANIC-DOS` | `HIGH` | `.rs`: Direct `.unwrap()` or `.expect()` on untrusted network/user inputs in server code. | Propagate errors cleanly using `?`, `.ok_or(...)`, or `match`. |
| `CVE-RUST-CMD-INJ` | `CWE-78 / CVE-RUST-CMD-INJ` | `CRITICAL` | `.rs`: `Command::new` invoked with unfiltered arguments. | Pass arguments as fixed slices without shell evaluation and validate against allowlists. |
| `CVE-PY-DESERIALIZE-RCE` | `CWE-502 / CVE-PY-DESERIALIZE-RCE` | `CRITICAL` | `.py`: `pickle.loads`, `pickle.load`, or `eval()` on untrusted payloads. | Replace `pickle` with `json` or schema-validated serialization; never `eval()` user data. |
| `CVE-PY-SHELL-INJ` | `CWE-78 / CVE-PY-SHELL-INJ` | `CRITICAL` | `.py`: `subprocess.*(..., shell=True)` or `os.system()`. | Use `subprocess.run([...], shell=False)` with explicit argument lists. |
| `CVE-PY-SSRF-UNVALIDATED` | `CWE-918 / CVE-PY-SSRF-UNVALIDATED` | `HIGH` | `.py`: `requests` / `httpx` call to unvalidated dynamic URL. | Enforce hostname allowlists and reject private/loopback/link-local resolved IPs. |
| `CVE-PY-UNTYPED-PAYLOAD` | `CWE-20 / CVE-PY-UNTYPED-PAYLOAD` | `HIGH` | `.py`: API handler accepting raw untyped `dict` payloads instead of strict schemas. | Validate request bodies using Pydantic v2 `BaseModel` schemas. |
| `CVE-PY-PATH-TRAVERSAL-ARCHIVE` | `CWE-22 / PATH-TRAVERSAL-ZIPSLIP` | `CRITICAL` | `.py`: `open()`, `send_file()`, `extractall()`, or `unpack_archive()` without `Path.resolve().is_relative_to(BASE_DIR)`. | Canonicalize target paths and verify `is_relative_to(BASE_DIR)` (or `filter='data'` on `tarfile`). |
| `CVE-PY-JINJA2-SSTI-INJECTION` | `CWE-1336 / JINJA2-SSTI-RCE` | `CRITICAL` | `.py`: Dynamic strings or f-strings passed to `render_template_string()` or `jinja2.Template()`. | Render static template files via `render_template()` with SandboxedEnvironment or context variables. |
| `CVE-PY-YAML-UNSAFE-LOAD` | `CWE-502 / YAML-UNSAFE-DESERIALIZATION` | `CRITICAL` | `.py`: `yaml.load()` without `Loader=SafeLoader` or `yaml.unsafe_load()`. | Always use `yaml.safe_load()` or `yaml.load(..., Loader=yaml.SafeLoader)`. |
| `CVE-PY-SQL-ALCHEMY-TEXT-INJECTION` | `CWE-89 / SQLALCHEMY-RAW-TEXT-INJECTION` | `CRITICAL` | `.py`: `sqlalchemy.text()` built via f-string, `+`, or `%` formatting. | Use bound parameters inside `text("... :param")` with `.bindparams(...)`. |
| `CVE-PY-JWT-NONE-ALGORITHM` | `CWE-327 / JWT-UNVERIFIED-NONE-ALGORITHM` | `CRITICAL` | `.py`: `jwt.decode()` with `verify=False`, `verify_signature=False`, or `'none'` algorithm. | Require signature verification and pin explicit asymmetric/HMAC algorithms (e.g. `algorithms=["RS256"]`). |
| `CVE-PY-PARAMIKO-MISSING-HOST-KEY` | `CWE-295 / PARAMIKO-AUTOADD-HOSTKEY-MITM` | `HIGH` | `.py`: Paramiko SSH client configured with `AutoAddPolicy()`. | Use `RejectPolicy()` backed by a pinned `known_hosts` file. |
| `CVE-PY-XML-XXE-ENTITY-EXPANSION` | `CWE-611 / XML-EXTERNAL-ENTITY-XXE` | `HIGH` | `.py`: `ElementTree` or `minidom` parsing untrusted XML without `defusedxml`. | Replace standard library XML parsers with `defusedxml.ElementTree`. |

### 3B. Architecture, Contracts & BLAKE3 Integrity (7 Rules)

| Rule ID | CWE / Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `BLAKE3_TAMPERED` | `CWE-353 / BLAKE3-INTEGRITY` | `CRITICAL` | `README.md` folder contract modified without matching BLAKE3 digest in `aether.lock.toml` (enforced in `ast-scanner/src/scanner.rs:934-965`). | Re-sign the updated contract via Cockpit Inspector / `/api/contracts/sign` or revert unauthorized edits. |
| `RULE_FORBIDDEN_IMPORT` | `CWE-1075 / ARCH-CONTRACT-VIOLATION` | `CRITICAL` | `use` / `import` / `from` matching `forbidden_imports` in the folder's `README.md` contract (`linter.rs:1543-1559`). | Remove the cross-layer import and inject dependencies through approved contract interfaces. |
| `RULE_MAX_LINES` | `CONTRACT / ARCH-BUDGET-EXCEEDED` | `WARNING` | File line count exceeds `effective_max_lines()` (`max_lines_per_file` / `file_max_lines` in `README.md`, `linter.rs:1425-1450`). | Split the file into smaller modular components or adjust the signed contract budget. |
| `RULE_FORBIDDEN_FUNCTION` | `CWE-1075 / ARCH-CONTRACT-VIOLATION` | `CRITICAL` | Call or macro matching `forbidden_functions` in the folder's `README.md` contract (`linter.rs:1562-1574`). | Replace the forbidden call with an approved abstraction or update `forbidden_functions` in the contract. |
| `RULE_FORBIDDEN_EXTENSION` | `CWE-1075 / ARCH-CONTRACT-VIOLATION` | `HIGH` | File extension in `forbidden_extensions` or missing from `allowed_extensions` (`linter.rs:1243-1259`). | Move/rename the file or update `allowed_extensions` / `forbidden_extensions` in the folder contract. |
| `RULE_MAX_FILES` | `CONTRACT / ARCH-BUDGET-EXCEEDED` | `WARNING` | Folder file count exceeds `max_files_per_folder` in its `README.md` contract (`linter.rs:1262-1286`). | Split the folder into sub-modules or raise `max_files_per_folder` in the folder contract. |
| `SAST_DIRECT_ENV_ACCESS` | `CWE-15 / DIRECT-ENV-ACCESS` | `HIGH` | `std::env::var`, `process.env`, or `os.environ` inside `domain` paths or folders with `security_rules.no_env_access: true`. | Pass configuration from the bootstrap/application layer rather than reading environment variables in pure domain code. |

### 3C. Front-End, Node.js & DOM (13 Rules)

| Rule ID | CWE / Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-JS-EVENTLOOP-REDOS-JSON` | `CWE-1333 / CWE-770-EVENTLOOP-DOS` | `CRITICAL` | `.js`/`.ts`: Unbounded `req.on('data')` stream accumulation without `MAX_BODY_SIZE` or unbounded dynamic RegExp. | Enforce strict body byte caps and reject oversized requests immediately. |
| `CVE-JS-XSS-DOM` | `CWE-79 / CVE-JS-XSS-DOM` | `HIGH` | `.js`/`.ts`/`.tsx`/`.jsx`: Raw `innerHTML`, `dangerouslySetInnerHTML`, or `document.write()`. | Use `textContent` or sanitize HTML via DOMPurify before rendering. |
| `CVE-JS-PROTO-POLLUTION` | `CWE-1321 / CVE-JS-PROTO-POLLUTION` | `HIGH` | `.js`/`.ts`: Untyped `: any` or raw `req.body` merging without schema validation or `__proto__` guard. | Validate inputs with Zod/Valibot and guard against `__proto__`/`constructor`/`prototype` keys. |
| `CVE-JS-CMD-INJ` | `CWE-78 / CVE-JS-CMD-INJ` | `CRITICAL` | `.js`/`.ts`: `child_process.exec` or `execSync` executing dynamic command strings. | Replace with `execFile` / `spawn(..., { shell: false })` and static argument arrays. |
| `CVE-JS-CODE-INJ` | `CWE-94 / CVE-JS-CODE-INJ` | `CRITICAL` | `.js`/`.ts`: `eval()` or `new Function()` on dynamic strings. | Eliminate dynamic code evaluation; use structured JSON parsing or safe dispatch tables. |
| `CVE-CLIENT-UNSAFE-ASSETS` | `CWE-829 / UNSAFE-ASSET-LOADING` | `MEDIUM` | `.js`/`.ts`: PixiJS / Three.js `Assets.load()` from unvalidated external URLs. | Restrict asset URLs to trusted origins/CDNs and verify integrity. |
| `CVE-JS-VM-SANDBOX-ESCAPE` | `CWE-94 / VM-SANDBOX-ESCAPE-RCE` | `CRITICAL` | `.js`/`.ts`: Node.js `vm.runInContext`, `vm.runInNewContext`, or `vm.Script` used as a security boundary. | Use `isolated-vm` or OS-level container/worker isolation instead of Node's `vm` module. |
| `CVE-JS-SSRF-DYNAMIC-AXIOS-FETCH` | `CWE-918 / AXIOS-FETCH-OUTBOUND-SSRF` | `CRITICAL` | `.js`/`.ts`: Outbound `axios`, `fetch`, `got`, or `http.get` to unvalidated dynamic URL. | Validate URL scheme/host against an allowlist and block private/metadata IPs (`169.254.169.254`). |
| `CVE-JS-PATH-TRAVERSAL-SENDFILE` | `CWE-22 / SENDFILE-PATH-TRAVERSAL` | `CRITICAL` | `.js`/`.ts`: `res.sendFile()` or `fs.readFile()` using `req.params`/`req.query` without root confinement. | Canonicalize via `path.resolve` and assert `resolved.startsWith(SAFE_ROOT + path.sep)`. |
| `CVE-JS-REGEX-DOS-DYNAMIC-INPUT` | `CWE-1333 / DYNAMIC-REGEXP-CATASTROPHIC-REDOS` | `HIGH` | `.js`/`.ts`: `new RegExp(userInput)` constructed directly from unescaped user input. | Escape metacharacters or use literal matching / RE2 (`re2` package). |
| `CVE-JS-CORS-WILDCARD-CREDENTIALS` | `CWE-942 / CORS-REFLECTED-ORIGIN-WITH-CREDENTIALS` | `HIGH` | `.js`/`.ts`: CORS configured with `credentials: true` alongside `origin: true` or reflected `Origin` headers. | Compare `Origin` against an explicit static allowlist of trusted origins. |
| `CVE-JS-UNHANDLED-PROMISE-CRASH` | `CWE-755 / ASYNC-ROUTE-UNHANDLED-REJECTION` | `HIGH` | `.js`/`.ts`: Async Express/Koa route handler without `try/catch` or `next(err)` forwarding. | Wrap async route handlers in `try/catch` and forward errors to centralized error middleware. |
| `CVE-JS-V8-TYPEDARRAY-SHARED-AB-RACE-OOB` | `V8-INTERNALS-CRITICAL / SHAREDARRAYBUFFER-TOCTOU-AND-ALLOCUNSAFE-BLEED` | `CRITICAL` | `.js`/`.ts`: `Buffer.allocUnsafe()` without `.fill(0)` or unsynchronized `SharedArrayBuffer` reads without `Atomics.load`. | Use `Buffer.alloc()` (zero-initialized) and `Atomics.load` / copy-before-validate on shared buffers. |

### 3D. C / C++ FFI & Network (11 Rules)

| Rule ID | CWE / Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-CPP-UNBOUNDED-COPY-UAF` | `CWE-120 / BUFFER-OVERFLOW-FFI` | `CRITICAL` | `.c`/`.cpp`/`.h`: Unbounded `strcpy`, `strcat`, `sprintf`, `gets`, or unchecked `memcpy`. | Use bounded `snprintf`, `strncpy` + null-termination, or `std::string` / `std::span`. |
| `CVE-CPP-NET-INTEGER-OVERFLOW-ALLOC` | `CWE-190 / INTEGER-OVERFLOW-ALLOC-OOM` | `CRITICAL` | `.c`/`.cpp`/`.h`: Arithmetic on packet lengths inside `malloc()` / `new char[]` without `UINT32_MAX` overflow guard. | Check `size > MAX_PACKET_SIZE` or use `size_t` overflow-safe math before allocating. |
| `CVE-CPP-NET-TYPE-PUNNING-STRICT-ALIASING` | `CWE-843 / STRICT-ALIASING-TYPE-PUNNING` | `HIGH` | `.c`/`.cpp`/`.h`: Casting raw byte buffer (`char*`/`uint8_t*`) directly via `reinterpret_cast<Header*>` or C cast. | Copy packet headers into aligned structs with `std::memcpy` or `std::bit_cast`. |
| `CVE-CPP-NET-ASYNC-CALLBACK-UAF` | `CWE-416 / ASYNC-EVENT-CALLBACK-UAF` | `CRITICAL` | `.cpp`/`.h`: Capturing raw `[this]` or `[&]` in `async_read`/`async_write`/`uv_queue_work` without `shared_from_this()`. | Capture `std::weak_ptr` / `shared_from_this()` and lock inside the async callback. |
| `CVE-CPP-NET-PARTIAL-READ-SHORT-FRAME` | `CWE-252 / UNCHECKED-SHORT-STREAM-READ` | `HIGH` | `.c`/`.cpp`/`.h`: Single `recv()`, `read()`, or `SSL_read()` assuming full frame delivery without loop or length check. | Loop until full frame bytes arrive and verify `bytes_read > 0`. |
| `CVE-CPP-NET-SOCKET-FD-LEAK-EXCEPTION` | `CWE-775 / SOCKET-FD-LEAK-EXCEPTION` | `HIGH` | `.cpp`/`.h`: Raw `int fd = socket(...)` / `accept(...)` in functions that allocate or `throw` without RAII wrapper. | Wrap socket descriptors in a RAII `UniqueFd` guard that closes on scope exit. |
| `CVE-CPP-NET-HOST-BYTE-ORDER-CONFUSION` | `CWE-1385 / MISSING-ENDIANNESS-CONVERSION` | `HIGH` | `.c`/`.cpp`/`.h`: Comparing or allocating from raw network `header.length` / `pkt->size` without `ntohs()` / `ntohl()`. | Convert multi-byte wire fields with `ntohs()` / `ntohl()` immediately on decode. |
| `CVE-CPP-NET-STRING-NULL-TERMINATION-OFF-BY-ONE` | `CWE-170 / MISSING-NULL-TERMINATION-LEAK` | `CRITICAL` | `.c`/`.cpp`/`.h`: Network `char[]` buffer passed to `strlen`, `std::string(buf)`, or `printf("%s")` without `buf[n] = '\0'`. | Reserve 1 byte for `'\0'` and explicitly null-terminate at `buf[bytes_read] = '\0'`. |
| `CVE-CPP-NET-FORMAT-STRING-LOGGING` | `CWE-134 / UNCONTROLLED-FORMAT-STRING-NET` | `CRITICAL` | `.c`/`.cpp`/`.h`: Network buffer passed directly as format string to `syslog`, `printf`, `sprintf`, or `fprintf`. | Always pass an explicit literal format string: `syslog(LOG_INFO, "%s", buf)`. |
| `CVE-CPP-NET-SOCKET-RACE-DOUBLE-CLOSE` | `CWE-415 / SOCKET-FD-RACE-DOUBLE-CLOSE` | `HIGH` | `.c`/`.cpp`/`.h`: `close(fd)` / `closesocket(fd)` without atomic `exchange(-1)` or mutex synchronization. | Use `std::atomic<int>` with `fd.exchange(-1)` before calling `close()`. |
| `CVE-CPP-NET-UNBOUNDED-RECURSION-TLV-PARSER` | `CWE-674 / UNBOUNDED-RECURSIVE-NET-PARSER` | `HIGH` | `.c`/`.cpp`/`.h`: Recursive TLV/JSON/BSON network parser lacking a `depth > MAX_DEPTH` cutoff. | Pass `depth` across recursive calls and abort cleanly once `depth > MAX_PARSE_DEPTH`. |

## 4. Deep Systems, ZK-SNARKs, Move/Wasm & Injection (27 Rules)

Defined in `crates/security-linter/src/deep_rules.rs` (`DeepSecurityRules::definitions()`, `L10–L253`).

| Rule ID | CWE / Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-ZK-WEAK-FIAT-SHAMIR` | `CWE-347 / WEAK-FIAT-SHAMIR-TRANSCRIPT-BYPASS` | `CRITICAL` | `.rs`/`.sol`: `challenge_scalar` / `squeeze_challenge` sampled before absorbing public inputs/instance/VK into Fiat-Shamir transcript. | Absorb all public inputs, commitments, and verifier keys via `transcript.append_message` before sampling challenges. |
| `CVE-ZK-UNDERCONSTRAINED-SIGNAL` | `CWE-682 / ZK-UNDERCONSTRAINED-CIRCUIT` | `CRITICAL` | `.circom`/`.rs`: Circom `<--` witness assignment without a matching `===` R1CS constraint within 5 lines. | Replace `<--` with `<==` or immediately add an explicit `signal === expression` constraint. |
| `CVE-DEFI-READ-ONLY-REENTRANCY` | `CWE-841 / DEFI-READ-ONLY-REENTRANCY` | `CRITICAL` | `.sol`: Calling `get_virtual_price()`, `getRate()`, or `getPoolTokens()` without reentrancy lock verification. | Apply `nonReentrant` or verify the pool's lock before consuming LP oracle prices. |
| `CVE-VM-ACCOUNT-CONFUSION-DISCRIMINATOR` | `CWE-843 / VM-ACCOUNT-CONFUSION-DISCRIMINATOR` | `CRITICAL` | `.rs`: `try_from_slice` / `unpack_from_slice` on `AccountInfo` without checking 8-byte discriminator or owner. | Validate the 8-byte account discriminator and owner or use typed `Account<'info, T>` wrappers. |
| `CVE-VM-MISSING-SIGNER-CHECK` | `CWE-287 / VM-MISSING-SIGNER-CHECK` | `CRITICAL` | `.rs`: Authority/admin `.key ==` check without asserting `account.is_signer` or `Signer<'info>`. | Require `authority.is_signer` or use a typed `Signer` account wrapper. |
| `CVE-RUST-UNSOUND-TRANSMUTE-ALIGNMENT` | `CWE-843 / RUST-UNSOUND-TRANSMUTE-ALIGNMENT` | `HIGH` | `.rs`: `transmute` or `slice::from_raw_parts` to higher-aligned types (`*const u64`/`u128`) without `align_of` / `align_to`. | Verify `ptr.align_offset(align_of::<T>()) == 0` or use `bytemuck::try_cast_slice()`. |
| `CVE-RUST-ASYNC-SELECT-CANCELLATION-CORRUPTION` | `CWE-662 / RUST-ASYNC-SELECT-CANCELLATION-CORRUPTION` | `CRITICAL` | `.rs`: `.write_all()`, `.read_exact()`, `.send_all()`, or `framed.send()` inside `tokio::select!`. | Buffer complete frames or isolate stream writing in a dedicated background task via `mpsc`. |
| `CVE-WASM-UNBOUNDED-STORAGE-ITERATION` | `CWE-400 / WASM-STORAGE-BOMB` | `HIGH` | `.rs`: `storage_plus` `.range()` / `.prefix()` iteration without `.take(LIMIT)` pagination. | Enforce bounded pagination (`.take(MAX_LIMIT)`) with a `start_after` cursor. |
| `CVE-EVM-L2-DATA-GAS-UNDERESTIMATION` | `CWE-682 / EVM-L2-DATA-GAS-UNDERESTIMATION` | `HIGH` | `.sol`: L2 relayer refund math using only `gasleft() * tx.gasprice` without querying `GasPriceOracle` L1 data fee. | Include `GasPriceOracle.getL1Fee(msg.data)` in L2 relayer fee calculations. |
| `CVE-ERC4337-PAYMASTER-STORAGE-POISONING` | `CWE-667 / ERC4337-PAYMASTER-STORAGE-POISONING` | `HIGH` | `.sol`: Accessing/mutating unassociated global storage inside `validatePaymasterUserOp`. | Restrict Paymaster validation to sender-associated storage slots per ERC-4337 rules. |
| `CVE-RUST-ARBITRARY-FILE-WRITE-TRAVERSAL` | `CWE-22 / RUST-ARBITRARY-FILE-WRITE-TRAVERSAL` | `CRITICAL` | `.rs`: `File::create` / `fs::write` / `jemalloc prof.dump` on dynamic paths without `canonicalize()` + `starts_with()`. | Canonicalize paths and enforce confinement within an allowed base directory. |
| `CVE-RUST-COMMAND-INJECTION-SHELL` | `CWE-78 / RUST-COMMAND-INJECTION-SHELL` | `CRITICAL` | `.rs`: `Command::new("sh"\|"bash"\|"cmd"\|"powershell")` with `-c` / `/C` and dynamic variables. | Invoke binaries directly without a shell interpreter and pass arguments separately. |
| `CVE-RUST-UNSOUND-SLICE-FROM-RAW-PARTS` | `CWE-119 / RUST-UNSOUND-SLICE-FROM-RAW-PARTS` | `CRITICAL` | `.rs`: `slice::from_raw_parts` or `Vec::from_raw_parts` without null, alignment, and bounds assertions. | Assert `!ptr.is_null()`, alignment, and `len <= MAX_SAFE_LEN` before constructing slices. |
| `CVE-RUST-UNBOUNDED-BCS-DESERIALIZE` | `CWE-502 / RUST-UNBOUNDED-BCS-DESERIALIZE` | `HIGH` | `.rs`: `bcs::from_bytes` without input length limit or recursion depth guard. | Bound input slice size and enforce maximum nested type depth before calling `bcs::from_bytes`. |
| `CVE-VM-NATIVE-UNSAFE-BUFFER-BOUNDS` | `CWE-787 / VM-NATIVE-UNSAFE-BUFFER-BOUNDS` | `CRITICAL` | `.rs`: Move VM native extension using `copy_nonoverlapping` or `.offset()` with unchecked transaction lengths. | Validate and clamp all offsets/lengths against slice capacities in safe Rust before copying. |
| `CVE-RUST-DYNAMIC-LIB-HIJACK` | `CWE-427 / RUST-DYNAMIC-LIB-HIJACK` | `CRITICAL` | `.rs`: `libloading::Library::new` / `dlopen` loading relative or untrusted `.so`/`.dll` paths. | Load libraries only from absolute, integrity-verified system paths. |
| `CVE-RUST-LLVM-DEAD-STORE-SECRET-LEAK` | `CWE-14 / LLVM-DSE-SECRET-ZEROIZATION-ELIMINATION` | `CRITICAL` | `.rs`: Zeroing keys/secrets via `.fill(0)` or `ptr::write_bytes(..., 0, ...)` without `zeroize` or volatile fence. | Use `zeroize::Zeroize` / `Zeroizing<T>` so LLVM Dead Store Elimination cannot strip wiping. |
| `CVE-RUST-UNWIND-PANIC-DOUBLE-DROP-UB` | `CWE-415 / RUST-UNWIND-PREMATURE-SET-LEN-DOUBLE-FREE` | `CRITICAL` | `.rs`: Premature `Vec::set_len(n)` before buffer population or `ptr::read()` without `ManuallyDrop`/RAII guard. | Call `set_len` only after full initialization or wrap ownership transitions in `ManuallyDrop`. |
| `CVE-RUST-MAYBEUNINIT-PADDING-AND-POISON-UB` | `CWE-908 / RUST-UNINIT-ASSUME-INIT-AND-STRUCT-PADDING-BLEED` | `CRITICAL` | `.rs`: `MaybeUninit::uninit().assume_init()`, `mem::uninitialized()`, or casting structs to `&[u8]` leaking padding bytes. | Initialize buffers with `MaybeUninit::zeroed()` and use `bytemuck::NoUninit` for byte serialization. |
| `CVE-RUST-ALLOC-LAYOUT-ZERO-OR-ISIZE-OVERFLOW` | `CWE-680 / RUST-ALLOCATOR-ZERO-LAYOUT-AND-ISIZE-OVERFLOW-UB` | `CRITICAL` | `.rs`: `std::alloc::alloc` on potential zero-sized `Layout` or `Layout::from_size_align_unchecked` without `isize::MAX` check. | Guard `layout.size() > 0` and construct layouts with checked `Layout::from_size_align`. |
| `CVE-RUST-FFI-PANIC-ACROSS-ABI-BOUNDARY` | `CWE-248 / RUST-EXTERN-C-UNWIND-ACROSS-FFI-UB` | `CRITICAL` | `.rs`: `extern "C" fn` containing `.unwrap()`, `.expect()`, `assert!`, or indexing without `catch_unwind`. | Wrap `extern "C" fn` bodies in `std::panic::catch_unwind` or use `extern "C-unwind"` deliberately. |
| `CVE-RUST-UNSAFECELL-CONCURRENT-MUT-NOALIAS-UB` | `CWE-362 / RUST-LLVM-NOALIAS-UNSAFECELL-MUT-UB` | `CRITICAL` | `.rs`: Returning or aliasing `&mut *cell.get()` from `UnsafeCell` under `&self` / `Sync` without synchronization. | Protect `UnsafeCell` access with `Mutex`/`RwLock` or atomic state machines. |
| `CVE-RUST-MMAP-EXTERNAL-TRUNCATION-SIGBUS` | `CWE-367 / RUST-MMAP-SLICE-TOCTOU-SIGBUS-AND-UB` | `HIGH` | `.rs`: `memmap2::Mmap::map` exposed as `&[u8]` without OS file lock (`flock` / `lock_exclusive`). | Prefer pread/buffered file I/O or acquire an OS exclusive lock before mapping immutable `&[u8]`. |
| `CVE-INJ-POSIX-FLAG-SMUGGLING` | `CWE-88 / POSIX-ARGUMENT-INJECTION-RCE` | `CRITICAL` | Polyglot: Executing `git`, `tar`, `find`, `rg`, `ssh`, `scp`, or `rsync` with dynamic args lacking `--` end-of-options delimiter. | Insert `"--"` before dynamic file/ref arguments and reject leading `'-'` characters. |
| `CVE-INJ-FILELESS-ESM-WASM-DESER` | `CWE-94 / FILELESS-DATA-IMPORT-AND-CWASM-RCE` | `CRITICAL` | JS/TS + `.rs`: Dynamic `import(specifier)` allowing `data:`/`blob:` URIs or `wasmtime::Module::deserialize` on unsigned `.cwasm`. | Allow only static/allowlisted module specifiers and verify cryptographic signatures before `.cwasm` deserialization. |
| `CVE-INJ-ARCHIVE-SYMLINK-ESCAPE` | `CWE-59 / ZIPSLIP-2-SYMLINK-CHAIN-ESCAPE` | `CRITICAL` | `.rs`/`.py`: `tar::Archive::unpack` without `unpack_in`/symlink rejection, or `tarfile.extractall` without `filter='data'`. | Reject symlink/hardlink entries during extraction and use `filter='data'` in Python `tarfile`. |
| `CVE-INJ-PROCESS-ENV-LOADER-POISON` | `CWE-426 / ENV-LOADER-PRELOAD-INJECTION` | `CRITICAL` | `.rs`/`.py`/`.js`: Spawning subprocesses with unfiltered user env maps that can set `LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONSTARTUP`, etc. | Clear or allowlist child environment variables and explicitly strip dynamic loader variables. |

## 5. PHP 8.x & Web Security (26 Rules)

Defined in `crates/security-linter/src/php_rules.rs` (`PhpSecurityRules::definitions()`, `L23–L280`), targeting `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps`.

| Rule ID | CWE / Taxonomy | Severity | Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-PHP-SQL-INJECTION` | `CWE-89 / SQL-INJECTION` | `CRITICAL` | Direct variable/superglobal concatenation into `PDO::query`, `PDO::exec`, `mysqli_query`, or `mysql_query`. | Use `$pdo->prepare()` with bound parameters (`bindParam` / `execute([...])`). |
| `CVE-PHP-COMMAND-INJECTION` | `CWE-78 / OS-COMMAND-INJECTION` | `CRITICAL` | `system()`, `exec()`, `passthru()`, `shell_exec()`, `proc_open()`, `popen()`, or backticks with unescaped input. | Escape arguments with `escapeshellarg()` or avoid shell invocations altogether. |
| `CVE-PHP-EVAL-CODE-INJECTION` | `CWE-94 / EVAL-CODE-INJECTION` | `CRITICAL` | `eval()`, `create_function()`, dynamic `assert()`, or `preg_replace()` with `/e` modifier. | Replace dynamic code execution with safe lookup tables or `preg_replace_callback()`. |
| `CVE-PHP-UNSERIALIZE-RCE` | `CWE-502 / OBJECT-INJECTION-RCE` | `CRITICAL` | `unserialize()` called without `['allowed_classes' => false]`. | Replace with `json_decode(..., true, 512, JSON_THROW_ON_ERROR)` or pass `['allowed_classes' => false]`. |
| `CVE-PHP-FILE-INCLUSION-RFI-LFI` | `CWE-98 / DYNAMIC-FILE-INCLUSION` | `CRITICAL` | Dynamic `include`, `include_once`, `require`, or `require_once` fed by user input. | Map keys through a strict static allowlist of permitted template/module files. |
| `CVE-PHP-PATH-TRAVERSAL` | `CWE-22 / ARBITRARY-FILE-ACCESS` | `HIGH` | `file_get_contents`, `readfile`, `file_put_contents`, `unlink`, or `fopen` without `basename()` / `realpath()` confinement. | Resolve with `realpath()` and verify the path starts with the confined base directory. |
| `CVE-PHP-XSS-UNESCAPED-OUTPUT` | `CWE-79 / REFLECTED-STORED-XSS` | `HIGH` | `echo`, `print`, or `<?=` outputting superglobals without `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`. | Contextually escape every dynamic HTML output with `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`. |
| `CVE-PHP-SSRF-CURL-STREAM` | `CWE-918 / SERVER-SIDE-REQUEST-FORGERY` | `HIGH` | `curl_exec`, `file_get_contents($url)`, or `fopen($url)` targeting unvalidated URLs. | Restrict schemes to `https`, validate hosts, and block RFC 1918/loopback/metadata IPs. |
| `CVE-PHP-UNRESTRICTED-FILE-UPLOAD` | `CWE-434 / UNRESTRICTED-FILE-UPLOAD` | `CRITICAL` | `move_uploaded_file()` preserving client `$_FILES[...]['name']` without extension allowlist or random rename. | Validate MIME/extension against an allowlist and store under a server-generated random filename outside webroot. |
| `CVE-PHP-XXE-LIBXML-INJECTION` | `CWE-611 / XML-EXTERNAL-ENTITY-INJECTION` | `HIGH` | `simplexml_load_string`, `simplexml_load_file`, or `DOMDocument::loadXML` with `LIBXML_NOENT` or without disabling entities. | Pass `LIBXML_NONET`, avoid `LIBXML_NOENT`, and disable external entity loading. |
| `CVE-PHP-SESSION-FIXATION-NO-REGEN` | `CWE-384 / SESSION-FIXATION` | `HIGH` | Assigning authenticated `$_SESSION['user_id']` / `$_SESSION['auth']` without `session_regenerate_id(true)`. | Call `session_regenerate_id(true)` immediately upon login or privilege elevation. |
| `CVE-PHP-COOKIE-SENSITIVE-PLAINTEXT` | `CWE-312 / INSECURE-COOKIE-TRANSMISSION` | `HIGH` | `setcookie()` or `session_set_cookie_params()` omitting or disabling `secure` / `httponly`. | Set `'secure' => true`, `'httponly' => true`, and `'samesite' => 'Lax'`/`'Strict'`. |
| `CVE-PHP-FILE-LOCKING-TOCTOU` | `CWE-362 / TOCTOU-FILE-RACE-CONDITION` | `HIGH` | `file_exists()` / `is_file()` followed by write without `flock($fp, LOCK_EX)` or atomic `'x'` mode. | Use atomic file creation (`fopen(..., 'xb')`) or acquire `flock($fp, LOCK_EX)`. |
| `CVE-PHP-BROKEN-CRYPTO-MD5-SHA1` | `CWE-327 / BROKEN-CRYPTOGRAPHIC-HASH` | `HIGH` | `md5()`, `sha1()`, or `crypt()` used for passwords, keys, or security tokens. | Use `password_hash($pw, PASSWORD_ARGON2ID)` for passwords and SHA-256/BLAKE2 for digests. |
| `CVE-PHP-HEADER-INJECTION-CRLF` | `CWE-113 / HTTP-RESPONSE-SPLITTING` | `HIGH` | `header()` containing unvalidated user input (`\r`, `\n`, or open redirect target). | Strip CR/LF bytes and validate redirect destinations against allowed local paths/domains. |
| `CVE-PHP-VARIABLE-OVERWRITE-EXTRACT` | `CWE-621 / VARIABLE-OVERWRITE-EXTRACT` | `CRITICAL` | `extract($_GET\|$_POST\|$_REQUEST)` without `EXTR_SKIP`, or variable-variables (`$$var = $_GET[...]`). | Never call `extract()` on external arrays; read explicit validated keys directly. |
| `CVE-PHP-MAIL-PARAM-INJECTION` | `CWE-88 / MAIL-PARAMETER-INJECTION` | `CRITICAL` | Native `mail()` with dynamic 5th argument (`$additional_params`) exposing sendmail `-X`/`-O` RCE flags. | Never pass user data to the 5th argument of `mail()`; use Symfony Mailer / PHPMailer. |
| `CVE-PHP-TEMPLATE-INJECTION-SSTI` | `CWE-1336 / SERVER-SIDE-TEMPLATE-INJECTION` | `CRITICAL` | `Twig::createTemplate`, `Blade::render`, or `Smarty::display('string:...')` compiling user-supplied templates. | Load templates exclusively from static files and pass user input solely as escaped context variables. |
| `CVE-PHP-DISABLED-SSL-VERIFY` | `CWE-295 / DISABLED-SSL-VERIFICATION` | `HIGH` | `CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => 0`, or `'verify_peer' => false`. | Keep TLS peer and hostname verification enabled against trusted CA bundles. |
| `CVE-PHP-TYPE-JUGGLING-AUTH` | `CWE-697 / LOOSE-COMPARISON-TYPE-JUGGLING` | `HIGH` | Loose `==` / `!=` / `strcmp(...) == 0` on passwords, HMACs, secrets, or tokens (`0e...` magic hashes). | Use `hash_equals($expected, $actual)` for tokens/HMACs and `password_verify()` for passwords. |
| `CVE-PHP-WEAK-PRNG-SECRETS` | `CWE-338 / CRYPTOGRAPHICALLY-WEAK-PRNG` | `HIGH` | `rand()`, `mt_rand()`, `uniqid()`, or `str_shuffle()` generating tokens, keys, or CSRF secrets. | Use cryptographically secure `random_bytes()` / `bin2hex(random_bytes(32))`. |
| `CVE-PHP-LDAP-INJECTION` | `CWE-90 / LDAP-INJECTION` | `HIGH` | `ldap_search()`, `ldap_list()`, or `ldap_read()` filters built by concatenating user input. | Escape filter values with `ldap_escape($val, '', LDAP_ESCAPE_FILTER)`. |
| `CVE-PHP-NOSQL-INJECTION` | `CWE-943 / NOSQL-INJECTION-MONGODB` | `HIGH` | Raw `$_POST`/`$_GET` arrays passed into MongoDB `$collection->find()`/`findOne()` allowing BSON `$ne` injection. | Cast scalar inputs explicitly `(string)` or validate structure before querying MongoDB. |
| `CVE-PHP-ZIP-SLIP-EXTRACTION` | `CWE-770 / ZIP-SLIP-ARBITRARY-EXTRACTION` | `HIGH` | `ZipArchive::extractTo()` without checking archive entry paths for `..` traversal. | Inspect every entry name with `realpath` confinement before extracting files. |
| `CVE-PHP-EXPOSED-DEBUG-CONFIG` | `CWE-209 / SENSITIVE-INFO-DEBUG-EXPOSURE` | `HIGH` | `ini_set('display_errors', '1')` or `phpinfo()` exposed in web endpoints. | Disable `display_errors` in production and remove `phpinfo()` diagnostic scripts. |
| `CVE-PHP-STREAM-WRAPPER-PHAR-FILTER` | `CWE-98 / PHAR-POLYGLOT-AND-FILTER-CHAIN-RCE` | `CRITICAL` | User-controlled URI/path passed to `file_exists`, `is_file`, `md5_file`, `getimagesize`, `exif_read_data`, or `copy` allowing `phar://` / `php://filter`. | Reject paths containing `://`, resolve relative to a fixed safe prefix, and sanitize filenames. |

## 6. Zig Systems & C-ABI (15 Rules)

Defined in `crates/security-linter/src/zig_rules.rs` (`ZigSecurityRules::definitions()`, `L17–L164`), targeting `.zig`.

| Rule ID | CWE / Taxonomy | Severity | Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-ZIG-USE-AFTER-FREE` | `CWE-416 / USE-AFTER-FREE-ALLOCATOR` | `CRITICAL` | `allocator.free(slice)`, `allocator.destroy(ptr)`, or `arena.deinit()` followed by dereference, indexing, or double-free. | Nullify or stop referencing freed memory immediately; prefer `defer` at allocation site. |
| `CVE-ZIG-UNHANDLED-ERROR-UNION` | `CWE-703 / UNHANDLED-ERROR-UNION` | `HIGH` | Discarding error unions with `_ = func()` or using `catch unreachable` on I/O, network, or allocation calls. | Propagate errors with `try` or handle failures explicitly via `catch \|err\| { ... }`. |
| `CVE-ZIG-INTEGER-OVERFLOW-WRAPPING` | `CWE-190 / INTEGER-OVERFLOW-WRAPPING` | `HIGH` | Wrapping operators (`+%`, `-%`, `*%`) or unchecked `@truncate` / `@intCast` on buffer sizes, indices, or amounts. | Use checked math (`std.math.add`/`mul`) or `@intCast` only after explicit range checks. |
| `CVE-ZIG-INSECURE-POINTER-CAST` | `CWE-843 / INSECURE-POINTER-TYPE-CONFUSION` | `CRITICAL` | `@ptrCast` or `@alignCast` on raw byte slices/addresses without size and alignment verification. | Use `std.mem.bytesAsValue` or assert alignment and buffer length before casting. |
| `CVE-ZIG-UNINITIALIZED-MEMORY` | `CWE-457 / UNINITIALIZED-MEMORY-ACCESS` | `HIGH` | Buffers/structs initialized with `= undefined` read or sent over network before explicit initialization. | Zero-initialize (`std.mem.zeroes`) or populate every byte before reading/transmitting. |
| `CVE-ZIG-BUFFER-OVERRUN-C-INTEROP` | `CWE-119 / C-INTEROP-BUFFER-OVERRUN` | `CRITICAL` | Passing non-sentinel `[]const u8` to C ABI functions expecting `[*:0]const u8`, raw `@ptrFromInt`, or `c.strcpy`/`c.sprintf`/`c.gets`. | Pass sentinel-terminated `[*:0]const u8` strings and replace unsafe C functions with bounded Zig slices. |
| `CVE-ZIG-UNPROTECTED-C-FORMAT-STRING` | `CWE-134 / UNPROTECTED-C-FORMAT-STRING` | `CRITICAL` | Dynamic/user string passed as format parameter to `c.printf`, `std.c.printf`, `c.snprintf`, `c.fprintf`, or `c.syslog`. | Always use a literal format string such as `c.printf("%s", str.ptr)`. |
| `CVE-ZIG-RAW-ALLOCATOR-LEAK` | `CWE-401 / RAW-ALLOCATOR-MEMORY-LEAK` | `HIGH` | `allocator.alloc()` or `allocator.create()` lacking matching `defer`/`errdefer` deallocation and not returned. | Pair every allocation with `defer` or `errdefer allocator.free(...)`. |
| `CVE-ZIG-COMMAND-INJECTION` | `CWE-78 / OS-COMMAND-INJECTION-CHILD` | `CRITICAL` | `std.process.Child.init` / `run` invoking `/bin/sh -c`, `bash -c`, `cmd.exe /c`, or `powershell` with dynamic input. | Pass executable path and argument array directly to `std.process.Child` without a shell. |
| `CVE-ZIG-PATH-TRAVERSAL` | `CWE-22 / PATH-TRAVERSAL-UNCONFINED-FS` | `HIGH` | `std.fs.path.join`, `std.fs.cwd().openFile`, or `deleteTree` using external input without `..` / `basename` confinement. | Extract `std.fs.path.basename` or verify canonicalized paths remain inside the target directory. |
| `CVE-ZIG-RUNTIME-SAFETY-DISABLED` | `CWE-676 / SET-RUNTIME-SAFETY-DISABLED-UB` | `HIGH` | Calling `@setRuntimeSafety(false)` disables bounds, overflow, and active-union checks. | Keep runtime safety enabled or isolate audited hot loops with explicit pre-checked bounds. |
| `CVE-ZIG-STACK-ADDRESS-RETURN` | `CWE-562 / STACK-USE-AFTER-RETURN-DANGLING` | `CRITICAL` | Returning `&local_buf` or slice `local_buf[0..]` pointing to a stack-allocated local array. | Allocate return buffers with an explicit `Allocator` or write into a caller-provided slice. |
| `CVE-ZIG-TLS-VERIFY-DISABLED` | `CWE-295 / TLS-CERTIFICATE-VERIFY-BYPASS` | `HIGH` | `tls_skip_verify = true`, `ca_bundle = .none`, or `verify = .none` in `std.http.Client` / `std.crypto.tls`. | Enable full certificate chain verification using system or pinned CA bundles. |
| `CVE-ZIG-WEAK-PRNG-CRYPTO` | `CWE-338 / INSECURE-PRNG-DEFAULTPRNG` | `HIGH` | `std.rand.DefaultPrng` or `Xoroshiro128` used to generate tokens, keys, nonces, or salts. | Replace with `std.crypto.random.bytes(...)`. |
| `CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB` | `CWE-125 / SIMD-VECTOR-OUT-OF-BOUNDS` | `HIGH` | Casting slice pointers to `@Vector(N, T)` via `@ptrCast` without `@alignCast` and `slice.len >= N` check. | Assert `slice.len >= N`, check alignment, or load scalar tail safely. |

## 7. C# / .NET / ASP.NET Core (20 Rules)

Defined in `crates/security-linter/src/csharp_rules.rs` (`CSharpSecurityRules::definitions()`, `L17–L214`), targeting `.cs`.

| Rule ID | CWE / Taxonomy | Severity | Detection Pattern | Remediation |
|---|---|---|---|---|
| `CVE-CS-INSECURE-DESERIALIZATION` | `CWE-502 / INSECURE-DESERIALIZATION-DOTNET` | `CRITICAL` | `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`, or `TypeNameHandling.Auto\|All\|Objects`. | Migrate to `System.Text.Json` and set `TypeNameHandling.None`. |
| `CVE-CS-SQL-INJECTION` | `CWE-89 / SQL-INJECTION-RAW-CONCAT` | `CRITICAL` | Interpolated (`$`) or concatenated (`+`) SQL passed to `SqlCommand`, `FromSqlRaw`, `ExecuteSqlRaw`, or Dapper. | Use parameterized `SqlParameter`s, `FromSqlInterpolated`, or Dapper anonymous parameter objects. |
| `CVE-CS-COMMAND-INJECTION` | `CWE-78 / OS-COMMAND-INJECTION` | `CRITICAL` | `Process.Start()` with concatenated arguments or `cmd.exe /c` / `powershell.exe` / `bash` shell invocation. | Set `UseShellExecute = false` and pass validated entries via `ProcessStartInfo.ArgumentList`. |
| `CVE-CS-PATH-TRAVERSAL` | `CWE-22 / PATH-TRAVERSAL-COMBINE` | `HIGH` | `Path.Combine(baseDir, userFile)` without `Path.GetFullPath()` prefix verification (leading `/` resets baseDir). | Resolve `Path.GetFullPath()` and verify `.StartsWith(baseFullPath + Path.DirectorySeparatorChar)`. |
| `CVE-CS-WEAK-CRYPTOGRAPHY` | `CWE-327 / WEAK-CRYPTOGRAPHIC-PRIMITIVE` | `HIGH` | `MD5`, `SHA1`, `DES`, `TripleDES`, `RC2`, or `CipherMode.ECB`. | Use `SHA256`/`SHA512` and `AesGcm` / `AES-CBC` with HMAC. |
| `CVE-CS-XSS-RAW-HTML` | `CWE-79 / XSS-RAW-HTML-INJECTION` | `HIGH` | `new HtmlString(...)`, `@Html.Raw(...)`, `(MarkupString)`, or `Response.Write(...)` disabling Razor/Blazor encoding. | Rely on default Razor `@val` encoding or sanitize HTML strictly with HtmlSanitizer. |
| `CVE-CS-XXE-INJECTION` | `CWE-611 / XML-EXTERNAL-ENTITY-INJECTION` | `HIGH` | `XmlDocument`, `XmlTextReader`, or `XPathDocument` with active `XmlUrlResolver` or `DtdProcessing.Parse`. | Set `XmlResolver = null` and `DtdProcessing = DtdProcessing.Prohibit`. |
| `CVE-CS-INSECURE-RANDOM` | `CWE-330 / INSUFFICIENTLY-RANDOM-PRNG` | `MEDIUM` | `System.Random` (`new Random()`) used for tokens, keys, nonces, or reset codes. | Use `System.Security.Cryptography.RandomNumberGenerator`. |
| `CVE-CS-LDAP-INJECTION` | `CWE-90 / LDAP-INJECTION-QUERY` | `HIGH` | Direct string concatenation into `DirectorySearcher.Filter`. | Escape Active Directory filter characters (`\`, `*`, `(`, `)`, `\0`) before building LDAP queries. |
| `CVE-CS-CSRF-DISABLED` | `CWE-352 / CSRF-PROTECTION-DISABLED` | `MEDIUM` | `[IgnoreAntiforgeryToken]` attribute on state-mutating ASP.NET Core controllers/actions. | Remove `[IgnoreAntiforgeryToken]` and enforce `[ValidateAntiForgeryToken]`. |
| `CVE-CS-SSRF-HTTPCLIENT` | `CWE-918 / SSRF-OUTBOUND-HTTPCLIENT` | `HIGH` | `HttpClient.GetAsync`/`GetStringAsync`/`SendAsync` or `WebClient.DownloadString` targeting unvalidated user URLs. | Validate hostnames against an allowlist and block private/loopback/metadata (`169.254.169.254`) IPs. |
| `CVE-CS-TLS-CERT-BYPASS` | `CWE-295 / TLS-SERVER-CERT-VALIDATION-BYPASS` | `CRITICAL` | `DangerousAcceptAnyServerCertificateValidator` or `ServerCertificateCustomValidationCallback` returning `true`. | Use default OS trust validation or pin specific SPKI certificate hashes. |
| `CVE-CS-JWT-VALIDATION-BYPASS` | `CWE-347 / JWT-TOKEN-VALIDATION-BYPASS` | `CRITICAL` | `TokenValidationParameters` with `ValidateIssuerSigningKey = false`, `RequireSignedTokens = false`, or `ValidateLifetime = false`. | Keep signing-key, signature requirement, and lifetime validation enabled. |
| `CVE-CS-OPEN-REDIRECT` | `CWE-601 / UNVALIDATED-OPEN-REDIRECT` | `HIGH` | `Redirect(returnUrl)` / `RedirectPermanent(url)` without `Url.IsLocalUrl()` or `LocalRedirect()`. | Use `LocalRedirect(returnUrl)` or enforce `Url.IsLocalUrl(returnUrl)`. |
| `CVE-CS-MASS-ASSIGNMENT` | `CWE-915 / ASPNET-OVERPOSTING-MASS-ASSIGNMENT` | `HIGH` | `TryUpdateModelAsync(model)` on domain entities without property allowlist or `[Bind]`. | Bind requests into dedicated DTOs or specify explicit `[Bind(...)]` / lambda property lists. |
| `CVE-CS-REDOS-UNBOUNDED-REGEX` | `CWE-1333 / REGEX-MISSING-TIMEOUT-REDOS` | `HIGH` | `new Regex(pattern)` or `Regex.IsMatch` without `matchTimeout` or `RegexOptions.NonBacktracking`. | Pass a bounded `TimeSpan` timeout or enable `RegexOptions.NonBacktracking` (.NET 7+). |
| `CVE-CS-HARDCODED-CREDENTIALS` | `CWE-798 / HARDCODED-SECRET-KEY-CONNSTRING` | `CRITICAL` | Hardcoded HMAC keys in `SymmetricSecurityKey` or literal `Password=...;` inside connection strings. | Load keys and connection strings from Secret Manager, Azure Key Vault, or environment configuration. |
| `CVE-CS-UNSAFE-STACKALLOC-OVERFLOW` | `CWE-787 / UNBOUNDED-STACKALLOC-CRASH-DOS` | `HIGH` | `stackalloc byte[dynamicLength]` with unbounded runtime length causing uncatchable `StackOverflowException`. | Enforce small constant stack limits (e.g. `<= 1024`) and rent larger buffers via `ArrayPool<byte>.Shared`. |
| `CVE-CS-UNSAFE-REFLECTION-INVOKE` | `CWE-470 / UNSAFE-TYPE-GETTYPE-ACTIVATOR-RCE` | `CRITICAL` | `Type.GetType(userType)` + `Activator.CreateInstance`, or `Assembly.LoadFrom(userPath)`. | Resolve types exclusively from an explicit static `Dictionary<string, Type>` allowlist. |
| `CVE-CS-SENSITIVE-ERROR-EXPOSURE` | `CWE-209 / EXCEPTION-STACKTRACE-EXPOSURE` | `MEDIUM` | Returning `ex.ToString()` or `ex.StackTrace` directly inside HTTP responses. | Log exception details server-side and return generic RFC 7807 `ProblemDetails` to clients. |

## 8. Novel `AETHER-*` Zero-Day & Covert Backdoor Detectors (28 Rules)

Defined in `crates/security-linter/src/epic_novel_rules.rs` (`EpicNovelRules::definitions()`, `L11–L264`). Note that `build.rs` is explicitly audited by `EpicNovelRules::audit_file` even though `is_test_file` normally excludes `build.rs`.

### 8A. Runtime & Compiler Soundness (6 Rules)

| Rule ID | AETHER Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `AETHER-RUST-ASYNC-TLS-BLEED` | `AETHER-EXEC-001 / ASYNC-WORKSTEAL-TLS-CONTAMINATION` | `CRITICAL` | `.rs`: Reading or mutating `thread_local!` inside an `async fn` across `.await` points. | Replace `thread_local!` with `tokio::task_local!` or pass explicit task context structs. |
| `AETHER-RUST-SERDE-INVARIANT-ERASURE` | `AETHER-TYPE-002 / SERDE-CONSTRUCTOR-INVARIANT-BYPASS` | `HIGH` | `.rs`: Struct with private fields and fallible `new`/`try_new` constructor deriving `Deserialize` / `BorshDeserialize` directly. | Use `#[serde(try_from = "RawStruct")]` or implement `Deserialize` manually to enforce invariants. |
| `AETHER-RUST-ASYNC-FRAME-SECRET-RESIDENCY` | `AETHER-COMP-003 / COROUTINE-FRAME-SECRET-GHOSTING` | `HIGH` | `.rs`: `Zeroizing`, `SigningKey`, or `PrivateKey` held across `.await` in an `async fn` state machine. | Drop secrets before `.await` or heap-box via `Box<Zeroizing<T>>` so coroutine moves do not ghost bytes. |
| `AETHER-PHP-PERSISTENT-WORKER-BLEED` | `AETHER-EXEC-004 / SHARED-NOTHING-RUNTIME-VIOLATION` | `CRITICAL` | `.php*`: User state/identity stored in `static` variables, static properties, or `$GLOBALS` under Octane/FrankenPHP/Swoole. | Store request-scoped state in per-request containers and implement `ResetInterface` cleanup. |
| `AETHER-PHP-GENERATOR-DEFERRED-GUARD` | `AETHER-CTRL-005 / LAZY-YIELD-AUTH-BYPASS` | `CRITICAL` | `.php*`: Authorization/validation guard (`throw`/`abort`/`isAdmin`) placed inside a function containing `yield`. | Execute all authorization checks in an eager wrapper function before returning the inner Generator. |
| `AETHER-PHP-PCRE-BACKTRACK-FAILOPEN` | `AETHER-CTRL-006 / PCRE-LIMIT-SILENT-FAIL-OPEN` | `HIGH` | `.php*`: `!preg_match()` / `preg_match() == 0` without checking `=== false` or `preg_last_error()`, or unchecked `preg_replace()`. | Explicitly check `=== false \|\| preg_last_error() !== PREG_NO_ERROR` and reject on error (fail-closed). |

### 8B. Invisible & Stealth Backdoors (4 Rules)

| Rule ID | AETHER Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `AETHER-STEALTH-UNICODE-TROJAN-SOURCE` | `AETHER-BACKDOOR-001 / INVISIBLE-BIDI-AND-ZERO-WIDTH-TROJAN` | `CRITICAL` | Polyglot: BiDi overrides (`U+202E`/`U+2066`), zero-width/Tag characters (`U+200B`/`U+E00xx`), or mixed ASCII+Cyrillic/Greek homoglyphs. | Strip all BiDi/invisible Unicode characters and normalize identifiers to pure ASCII/single script. |
| `AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR` | `AETHER-BACKDOOR-002 / PREMAIN-LINK-SECTION-INIT-ARRAY` | `CRITICAL` | `.rs` (incl. `build.rs`): `#[link_section = ".init_array"]`/`.ctors`, `#[ctor]`, or `#[no_mangle]`/`#[export_name]` hijacking libc/crypto/PAM symbols. | Remove pre-main ELF constructors and unauthorized `#[no_mangle]` symbol exports. |
| `AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR` | `AETHER-BACKDOOR-003 / COMPILE-TIME-LATERAL-DROPPER` | `CRITICAL` | `.rs` (`build.rs` & proc-macros): Network sockets, shells, CI/SSH/AWS secret reads, or payload generation in `OUT_DIR` at compile time. | Restrict `build.rs` and proc-macros to deterministic local codegen/linking without network or secret access. |
| `AETHER-PHP-STEALTH-ENGINE-BACKDOOR` | `AETHER-BACKDOOR-004 / PHP-TICK-AUTOLOAD-VARFUNC-STEALTH` | `CRITICAL` | `.php*`: `register_tick_function`, dynamic shutdown hooks, obfuscated variable-function calls (`base64`/`gzinflate`/`chr`), or `stream_wrapper`/`spl_autoload` hijack. | Remove dynamic tick/autoload hooks and obfuscated variable-function dispatchers. |

### 8C. Covert Non-CWE RCE Backdoors (6 Rules)

| Rule ID | AETHER Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `AETHER-PHP-FFI-NATIVE-BRIDGE-RCE` | `AETHER-RCE-001 / PHP-FFI-SHELLCODE-LIBC-BYPASS` | `CRITICAL` | `.php*`: `FFI::cdef`/`load`/`cast` calling `system`, `execve`, `mmap`, `mprotect`, `VirtualAlloc`, or `dlopen` bypassing `disable_functions`. | Disable PHP FFI in production (`ffi.enable=false`) and remove native libc/shellcode bridges. |
| `AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE` | `AETHER-RCE-002 / CRYPTO-GATED-NO-EVAL-SINK-TRAPDOOR` | `CRITICAL` | `.php*`: Exotic execution sinks (`ob_start` callback, `mb_ereg_replace` `e`, `sqliteCreateFunction`, `pcntl_exec`, `yaml_parse`, `include data://`). | Eliminate exotic dynamic callbacks and disable `data://` includes and `pcntl_exec`. |
| `AETHER-PHP-OPCACHE-USERINI-PERSIST-RCE` | `AETHER-RCE-003 / INI-PREPEND-OPCACHE-STEALTH-PERSIST` | `CRITICAL` | `.php*`: Dynamic writes/directives targeting `.user.ini`, `php.ini`, `.htaccess`, `auto_prepend_file`, `opcache.preload`, or `opcache_compile_file()`. | Lock down webroot `.ini`/`.htaccess` write permissions and never pass dynamic paths to `opcache_compile_file()`. |
| `AETHER-RUST-FILELESS-WX-MEMFD-RCE` | `AETHER-RCE-004 / RUST-FILELESS-MMAP-MEMFD-EXEC` | `CRITICAL` | `.rs` (incl. `build.rs`): `PROT_EXEC` / `PAGE_EXECUTE_READWRITE` W^X violations, `memfd_create` + `fexecve`, `/proc/self/mem` writes, or `transmute` to `extern "C" fn()`. | Enforce strict W^X memory policies and forbid fileless shellcode execution primitives. |
| `AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE` | `AETHER-RCE-005 / ZERO-COPY-ARCHIVED-VTABLE-HIJACK` | `CRITICAL` | `.rs`: `rkyv::archived_root`, `access_unchecked`, or `deserialize_unchecked` without bytecheck validation. | Always use validated `rkyv::check_archived_root` / `rkyv::access::<T, rancor::Error>` on untrusted bytes. |
| `AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE` | `AETHER-RCE-006 / GLOBAL-ALLOC-PANIC-SIGNAL-TRAPDOOR` | `CRITICAL` | `.rs` (incl. `build.rs`): `impl GlobalAlloc`, `std::panic::set_hook`, or `sigaction` containing network, shell, FFI, or `PROT_EXEC` calls. | Keep global allocators, panic hooks, and signal handlers strictly minimal and free of I/O or exec calls. |

### 8D. Rust Semantic Gems (6 Rules)

| Rule ID | AETHER Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `AETHER-RUST-EPHEMERAL-LOCK-DROP` | `AETHER-SYNC-007 / EPHEMERAL-MUTEX-GUARD-DROP` | `CRITICAL` | `.rs`: `let _ = mutex.lock()` (or `.write()` / `.read()`), which drops the RAII guard at the semicolon before the critical section. | Bind the guard to a named variable (`let _guard = mutex.lock();`) spanning the critical section. |
| `AETHER-RUST-PATH-JOIN-PREFIX-WIPE` | `AETHER-PATH-008 / PATH-JOIN-ABSOLUTE-OVERWRITE` | `CRITICAL` | `.rs`: `PathBuf::join` / `push` with untrusted input containing a leading `/` or Windows prefix silently wiping the base directory. | Strip roots/prefixes or use `PathGuard` canonical `starts_with` confinement. |
| `AETHER-RUST-ASSERT-UNWINDSAFE-STATE-TORN` | `AETHER-PANIC-009 / ASSERT-UNWINDSAFE-MUT-CORRUPTION` | `HIGH` | `.rs`: Wrapping `&mut` state in `AssertUnwindSafe` inside `panic::catch_unwind`, leaving torn invariants after a panic. | Avoid `AssertUnwindSafe` on security/balance state or rebuild invariants cleanly on unwind. |
| `AETHER-RUST-UTF8-LOSSY-SMUGGLING` | `AETHER-NORM-010 / UTF8-LOSSY-REPLACEMENT-COLLISION` | `HIGH` | `.rs`: `String::from_utf8_lossy` collapsing distinct invalid byte sequences into `U+FFFD` in auth, HMAC, or filter paths. | Validate strict UTF-8 with `std::str::from_utf8` or operate directly on raw byte slices `&[u8]`. |
| `AETHER-RUST-UNANCHORED-REGEX-GATE` | `AETHER-CTRL-011 / REGEX-SUBSTRING-IS-MATCH-BYPASS` | `HIGH` | `.rs`: `Regex::is_match` on allowlist/origin/role checks without strict `\A...\z` anchors (`^`/`$` fails in multiline mode). | Anchor security regexes strictly with `\A` and `\z`. |
| `AETHER-RUST-RELAXED-ATOMIC-SECURITY-GATE` | `AETHER-MEM-012 / WEAK-RELAXED-ATOMIC-SECURITY-BARRIER` | `HIGH` | `.rs`: `Ordering::Relaxed` on atomic security/init flags (`auth`, `admin`, `init`, `ready`, `sealed`) allowing CPU reordering on ARM64/RISC-V. | Use `Ordering::Acquire` on loads and `Ordering::Release` (or `SeqCst`) on stores. |

### 8E. PHP / Zend Semantic Gems (6 Rules)

| Rule ID | AETHER Taxonomy | Severity | Target & Detection Pattern | Remediation |
|---|---|---|---|---|
| `AETHER-PHP-LOOSE-INARRAY-BOOL-BYPASS` | `AETHER-ZEND-007 / PHP8-INARRAY-BOOL-TRUE-JUGGLING` | `CRITICAL` | `.php*`: `in_array()` or `array_search()` on roles/actions/algorithms without 3rd parameter `$strict = true`. | Always pass `true` as the third argument: `in_array($val, $allowed, true)`. |
| `AETHER-PHP-PARSE-URL-DIFFERENTIAL-SSRF` | `AETHER-ZEND-008 / PARSE-URL-LIBCURL-HOST-DIFFERENTIAL` | `CRITICAL` | `.php*`: Validating host via `parse_url()` then passing raw URL to `curl`/`file_get_contents` without post-DNS IP check. | Resolve DNS, block `FILTER_FLAG_NO_PRIV_RANGE \| FILTER_FLAG_NO_RES_RANGE`, pin via `CURLOPT_RESOLVE`, and disable redirects. |
| `AETHER-PHP-ESCAPESHELLCMD-FLAG-RCE` | `AETHER-ZEND-009 / ESCAPESHELLCMD-ARGUMENT-FLAG-INJECTION` | `CRITICAL` | `.php*`: Using `escapeshellcmd()` instead of `escapeshellarg()`, allowing space-separated CLI flag smuggling (`--checkpoint-action=exec=...`). | Escape each individual argument with `escapeshellarg()` and insert `--` before user args. |
| `AETHER-PHP-JSON-DEPTH-NULL-FAILOPEN` | `AETHER-ZEND-010 / JSON-DECODE-DEPTH512-SILENT-NULL` | `HIGH` | `.php*`: `json_decode()` without `JSON_THROW_ON_ERROR`, returning `null` silently on depth `> 512` or malformed UTF-8. | Pass `JSON_THROW_ON_ERROR` and catch `JsonException` explicitly. |
| `AETHER-PHP-PDO-EMULATED-PREPARES-SMUGGLING` | `AETHER-ZEND-011 / PDO-CLIENT-EMULATED-PREPARE-SMUGGLING` | `HIGH` | `.php*`: PDO MySQL leaving `PDO::ATTR_EMULATE_PREPARES` enabled (`true`), risking multi-query and charset-differential SQLi. | Set `PDO::ATTR_EMULATE_PREPARES => false` and specify `charset=utf8mb4` in the DSN. |
| `AETHER-PHP-CURLY-VAR-INTERPOLATION-RCE` | `AETHER-ZEND-012 / PHP-COMPLEX-CURLY-SYNTAX-EXEC` | `CRITICAL` | `.php*`: Complex curly syntax `{${func()}}` or `${$_...}` inside double-quoted strings or heredocs. | Never interpolate external variables via `{${...}}` or embed dynamic inputs inside double quotes/heredocs. |

## 9. Embedded Semgrep Community OWASP/CWE Bundle (24 Rules)

Defined in `crates/security-linter/rules/community_owasp_cwe.yaml` (`L4–L316`). Note that `SemgrepImporter::convert_rule` (`semgrep_importer.rs:125-133`) maps YAML `ERROR`/`CRITICAL` -> **`CRITICAL`** and `WARNING` -> **`HIGH`**.

| Rule ID | CWE | YAML Severity -> Imported | Languages | Matched Patterns |
|---|---|---|---|---|
| `semgrep-owasp-sqli-format` | `CWE-89` | `ERROR` -> `CRITICAL` | `python, php, javascript, typescript` | `cursor.execute($QUERY)`, `db.query($QUERY)`, `mysqli_query($CONN, $SQL)` |
| `semgrep-owasp-command-injection` | `CWE-78` | `CRITICAL` -> `CRITICAL` | `python, javascript, typescript, rust, php` | `os.system(...)`, `child_process.exec(...)`, `exec($CMD)`, `system($CMD)`, `Command::new("sh").arg("-c").arg($CMD)` |
| `semgrep-owasp-xss-innerhtml` | `CWE-79` | `ERROR` -> `CRITICAL` | `javascript, typescript` | `$ELEM.innerHTML = $INPUT`, `$ELEM.outerHTML = $INPUT`, `document.write(...)` |
| `semgrep-owasp-path-traversal` | `CWE-22` | `ERROR` -> `CRITICAL` | `python, javascript, typescript, php` | `open($PATH, ...)`, `fs.readFile($PATH, ...)`, `fs.readFileSync($PATH, ...)`, `include($PATH)`, `require($PATH)` |
| `semgrep-owasp-deserialization-pickle` | `CWE-502` | `CRITICAL` -> `CRITICAL` | `python, php` | `pickle.loads($PAYLOAD)`, `pickle.load($PAYLOAD)`, `unserialize($PAYLOAD)` |
| `semgrep-owasp-deserialization-yaml` | `CWE-502` | `ERROR` -> `CRITICAL` | `python` | `yaml.load($INPUT, Loader=yaml.Loader)` |
| `semgrep-owasp-hardcoded-secret` | `CWE-798` | `CRITICAL` -> `CRITICAL` | `python, javascript, typescript, rust, php, go` | `api_key = "$SECRET"`, `password = "$SECRET"`, `jwt_secret = "$SECRET"`, `bearer_token = "$SECRET"` |
| `semgrep-owasp-broken-crypto-jwt-none` | `CWE-327` | `CRITICAL` -> `CRITICAL` | `python, javascript, typescript` | `jwt.decode(..., algorithms=['none'], ...)`, `jwt.verify(..., { algorithms: ["none"] }, ...)` |
| `semgrep-owasp-weak-hash-md5-sha1` | `CWE-328` | `WARNING` -> `HIGH` | `python, javascript, typescript, rust, php` | `hashlib.md5(...)`, `hashlib.sha1(...)`, `crypto.createHash("md5"\|"sha1")`, `md5($INPUT)` |
| `semgrep-owasp-ssrf-unvalidated-url` | `CWE-918` | `ERROR` -> `CRITICAL` | `python, javascript, typescript, rust, php, go` | `requests.get/post($URL, ...)`, `axios.get/post($URL, ...)`, `fetch($URL, ...)`, `file_get_contents($URL)` |
| `semgrep-owasp-code-injection-eval` | `CWE-94` | `CRITICAL` -> `CRITICAL` | `python, javascript, typescript, php` | `eval($CODE)`, `exec($CODE)`, `new Function($CODE)` |
| `semgrep-owasp-auth-bypass-mock` | `CWE-287` | `CRITICAL` -> `CRITICAL` | `python, javascript, typescript, rust, go` | `is_authenticated = True`, `skip_auth = true`, `bypass_auth = true` |
| `semgrep-owasp-xxe-xml-external-entity` | `CWE-611` | `ERROR` -> `CRITICAL` | `python, php` | `etree.XMLParser(resolve_entities=True, ...)`, `xml.sax.make_parser(...)` |
| `semgrep-owasp-log-injection-crlf` | `CWE-117` | `WARNING` -> `HIGH` | `python, javascript, typescript, java` | `logger.info($MSG)`, `logging.info($MSG)`, `console.log($MSG)` |
| `semgrep-owasp-stacktrace-exposure` | `CWE-209` | `WARNING` -> `HIGH` | `python, javascript, typescript, php` | `traceback.print_exc()`, `res.send(err.stack)` |
| `semgrep-owasp-cookie-missing-httponly` | `CWE-1004` | `WARNING` -> `HIGH` | `javascript, typescript, python, php` | `res.cookie($NAME, $VAL, { httpOnly: false })`, `setcookie($NAME, $VAL, 0, "", "", false, false)` |
| `semgrep-owasp-insecure-curl-pipe-bash` | `CWE-494` | `ERROR` -> `CRITICAL` | `python, javascript, rust` | `curl ... \| bash`, `wget ... \| sh` |
| `semgrep-cwe-integer-overflow-truncation` | `CWE-190` | `WARNING` -> `HIGH` | `rust, c, cpp` | `($X as u16)`, `($X as u8)` |
| `semgrep-cwe-use-after-free-pointer` | `CWE-416` | `CRITICAL` -> `CRITICAL` | `c, cpp, rust` | `free($PTR)`, `drop($PTR)` |
| `semgrep-cwe-null-pointer-deref` | `CWE-476` | `ERROR` -> `CRITICAL` | `c, cpp, rust` | `*$PTR`, `unsafe { *$PTR }` |
| `semgrep-cwe-race-condition-toctou` | `CWE-362` | `WARNING` -> `HIGH` | `python, php, c, cpp` | `os.path.exists($PATH)`, `file_exists($PATH)` |
| `semgrep-cwe-buffer-overflow-strcpy` | `CWE-787` | `CRITICAL` -> `CRITICAL` | `c, cpp, zig` | `strcpy($DEST, $SRC)`, `strcat($DEST, $SRC)`, `sprintf($BUF, ...)`, `c.strcpy($DEST, $SRC)` |
| `semgrep-csharp-binaryformatter-deser` | `CWE-502` | `CRITICAL` -> `CRITICAL` | `csharp` | `new BinaryFormatter()`, `new NetDataContractSerializer()`, `TypeNameHandling.All` |
| `semgrep-zig-unsafe-ptrcast-runtime` | `CWE-843` | `HIGH` -> `HIGH` | `zig` | `@setRuntimeSafety(false)`, `@intToPtr($TYPE, $VAL)` |

## Related Guides

{% content-ref url="cwe-sast-engine.md" %}
[CWE & SAST Engine](cwe-sast-engine.md)
{% endcontent-ref %}

{% content-ref url="../plugins/semgrep-and-community-bundle.md" %}
[Semgrep Importer & Community Bundle](../plugins/semgrep-and-community-bundle.md)
{% endcontent-ref %}

{% content-ref url="../plugins/sast-taint-dsl.md" %}
[Declarative SAST & Taint DSL v2](../plugins/sast-taint-dsl.md)
{% endcontent-ref %}
