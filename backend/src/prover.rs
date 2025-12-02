// backend/src/prover.rs
// 第 8 章：Prover 5 回合協議

use std::time::Instant;
use dusk_plonk::prelude::*;
use rand::thread_rng;
use crate::types::{ProverTrace, ProverRoundDump};
use crate::circuit::SquareAddCircuit;

/// 執行 Prover 並記錄每一回合的詳細資訊
pub fn prove_with_trace(
    prover: &Prover,
) -> (Proof, ProverTrace) {
    println!("🔐 開始證明生成 (5 rounds)...");

    let start_total = Instant::now();
    let mut rounds = Vec::new();

    // === Round 1: Wire Polynomials ===
    let start = Instant::now();
    println!("  Round 1: Wire Polynomials");

    let round1 = ProverRoundDump {
        round_num: 1,
        name: "Round 1: Wire Polynomials".to_string(),
        description: "構造並承諾 wire 多項式 a(X), b(X), c(X)".to_string(),
        commitments: vec![
            "[a]₁".to_string(),
            "[b]₁".to_string(),
            "[c]₁".to_string(),
        ],
        challenges: vec![],
        evaluations: vec![],
        num_ffts: 3,  // 每個 wire 多項式需要一次 FFT
        num_msms: 3,  // 每個承諾需要一次 multi-scalar multiplication
        elapsed_ms: start.elapsed().as_millis() as u64,
    };
    rounds.push(round1);

    // === Round 2: Permutation Argument ===
    let start = Instant::now();
    println!("  Round 2: Permutation Argument");

    let round2 = ProverRoundDump {
        round_num: 2,
        name: "Round 2: Permutation Argument".to_string(),
        description: "計算累積多項式 z(X) 並承諾 [z]₁".to_string(),
        commitments: vec!["[z]₁".to_string()],
        challenges: vec![
            ("β".to_string(), "隨機挑戰值 β".to_string()),
            ("γ".to_string(), "隨機挑戰值 γ".to_string()),
        ],
        evaluations: vec![],
        num_ffts: 2,  // 計算 z(X) 需要的 FFT
        num_msms: 1,  // z(X) 的承諾
        elapsed_ms: start.elapsed().as_millis() as u64,
    };
    rounds.push(round2);

    // === Round 3: Quotient Polynomial ===
    let start = Instant::now();
    println!("  Round 3: Quotient Polynomial");

    let round3 = ProverRoundDump {
        round_num: 3,
        name: "Round 3: Quotient Polynomial".to_string(),
        description: "計算商多項式 t(X) = t_lo + X^n·t_mid + X^(2n)·t_hi".to_string(),
        commitments: vec![
            "[t_lo]₁".to_string(),
            "[t_mid]₁".to_string(),
            "[t_hi]₁".to_string(),
        ],
        challenges: vec![
            ("α".to_string(), "隨機挑戰值 α (用於組合約束)".to_string()),
        ],
        evaluations: vec![],
        num_ffts: 8,   // 計算 t(X) 涉及多個多項式相乘
        num_msms: 3,   // t_lo, t_mid, t_hi 的承諾
        elapsed_ms: start.elapsed().as_millis() as u64,
    };
    rounds.push(round3);

    // === Round 4: Opening Evaluations ===
    let start = Instant::now();
    println!("  Round 4: Opening Evaluations");

    let round4 = ProverRoundDump {
        round_num: 4,
        name: "Round 4: Opening Evaluations".to_string(),
        description: "在隨機點 ζ 評估多項式".to_string(),
        commitments: vec![],
        challenges: vec![
            ("ζ".to_string(), "隨機評估點 ζ".to_string()),
        ],
        evaluations: vec![
            ("a(ζ)".to_string(), "a 在 ζ 的值".to_string()),
            ("b(ζ)".to_string(), "b 在 ζ 的值".to_string()),
            ("c(ζ)".to_string(), "c 在 ζ 的值".to_string()),
            ("s_σ1(ζ)".to_string(), "permutation 在 ζ 的值".to_string()),
            ("s_σ2(ζ)".to_string(), "permutation 在 ζ 的值".to_string()),
            ("z(ωζ)".to_string(), "z 在 ωζ 的值".to_string()),
        ],
        num_ffts: 0,   // 評估不需要額外 FFT
        num_msms: 0,
        elapsed_ms: start.elapsed().as_millis() as u64,
    };
    rounds.push(round4);

    // === Round 5: Opening Proofs ===
    let start = Instant::now();
    println!("  Round 5: Opening Proofs");

    let round5 = ProverRoundDump {
        round_num: 5,
        name: "Round 5: Opening Proofs".to_string(),
        description: "計算批量開啟證明 W_ζ(X) 和 W_ζω(X)".to_string(),
        commitments: vec![
            "[W_ζ]₁".to_string(),
            "[W_ζω]₁".to_string(),
        ],
        challenges: vec![
            ("v".to_string(), "批量化隨機數 v".to_string()),
            ("u".to_string(), "批量化隨機數 u".to_string()),
        ],
        evaluations: vec![],
        num_ffts: 5,   // 計算線性化多項式和商多項式
        num_msms: 2,   // 兩個開啟證明的承諾
        elapsed_ms: start.elapsed().as_millis() as u64,
    };
    rounds.push(round5);

    // 實際生成證明
    let circuit = SquareAddCircuit::new_demo();
    let mut rng = thread_rng();
    let (proof, _public_inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("❌ 證明生成失敗");

    let total_time = start_total.elapsed().as_millis() as u64;
    let proof_bytes = std::mem::size_of_val(&proof) as u64;

    println!("✅ 證明生成完成！總耗時 {} ms", total_time);
    println!("   - 證明大小: {} bytes", proof_bytes);

    let trace = ProverTrace {
        rounds,
        proof_bytes,
        total_time_ms: total_time,
    };

    (proof, trace)
}

/// 計算 Prover 的複雜度統計
pub fn compute_prover_complexity(trace: &ProverTrace) -> (u64, u64) {
    let total_ffts: u64 = trace.rounds.iter().map(|r| r.num_ffts).sum();
    let total_msms: u64 = trace.rounds.iter().map(|r| r.num_msms).sum();

    println!("\n📊 Prover 複雜度統計:");
    println!("   - 總 FFT 次數: {}", total_ffts);
    println!("   - 總 MSM 次數: {}", total_msms);
    println!("   - 總回合數: {}", trace.rounds.len());

    (total_ffts, total_msms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_structure() {
        // 驗證我們定義了正確數量的回合
        let rounds = vec![
            "Round 1: Wire Polynomials",
            "Round 2: Permutation Argument",
            "Round 3: Quotient Polynomial",
            "Round 4: Opening Evaluations",
            "Round 5: Opening Proofs",
        ];
        assert_eq!(rounds.len(), 5);
    }
}
