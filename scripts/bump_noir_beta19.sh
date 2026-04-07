#!/usr/bin/env bash
#
# Bump co-snarks from Noir beta.17 to beta.19 (Aztec 4.2.0 compatible).
#
# WHY BETA.19 AND NOT BETA.18:
#   Aztec 4.2.0 ships a custom nargo at commit 19093143 which is
#   post-beta.19 (despite reporting as beta.18 in --version).
#   Key differences:
#     - beta.18 has ExpressionWidth field; Aztec's nargo doesn't
#     - beta.19 removed ExpressionWidth, matching Aztec's nargo
#     - beta.19 changed MemoryAddress from usize to u32 (brillig)
#     - bb 4.2.0 handles both formats fine
#
# BETA.19 DEPENDENCY FIX:
#   Only one RC pin needed: keccak 0.2.0 -> 0.2.0-rc.0
#   (The keccak crate renamed f1600 between RC and stable)
#
# CO-SNARKS CODE CHANGES NEEDED:
#   - co-brillig: MemoryAddress::Direct(usize) -> Direct(u32)
#   - co-brillig: HeapArray.size usize -> SemanticLength
#   - co-acvm: Remove ExpressionWidth import/constant
#   - co-acvm: BrilligCall predicate Option<Expression> -> Expression
#
# USAGE:
#   cd /path/to/frov-co-snarks
#   bash scripts/bump_noir_beta19.sh
#
# TO REVERT:
#   git checkout Cargo.toml Cargo.lock

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Step 1: Bump Cargo.toml to beta.19 ==="
sed -i '' 's/v1.0.0-beta.17/v1.0.0-beta.19/g; s/1.0.0-beta.17/1.0.0-beta.19/g' Cargo.toml
grep 'beta.19' Cargo.toml | head -1
echo ""

echo "=== Step 2: Regenerate Cargo.lock ==="
rm -f Cargo.lock
cargo generate-lockfile 2>&1 | tail -1
echo ""

echo "=== Step 3: Pin keccak to RC (only pin needed) ==="
cargo update -p keccak@0.2.0 --precise 0.2.0-rc.0 2>&1 | grep -E "Down|error" || true
echo ""

echo "=== Step 4: Verify compilation ==="
cargo check 2>&1 | tail -3

echo ""
echo "Done. If co-brillig/co-acvm errors remain, apply the code fixes."
echo "Run 'cargo test --release -p tests -- proof_tests' to verify."
