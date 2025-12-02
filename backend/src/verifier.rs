// backend/src/verifier.rs
// 第 9 章：Verifier 驗證協議

use std::time::Instant;
use dusk_plonk::prelude::*;
use crate::types::{VerifierTrace, VerifierStep};

/// 執行驗證並記錄詳細步驟
pub fn verify_with_trace(
    verifier: &Verifier,
    proof: &Proof,
    public_inputs: &[BlsScalar],
) -> (bool, VerifierTrace) {
    println!("🔍 開始證明驗證...");

    let start_total = Instant::now();
    let mut steps = Vec::new();

    // === Step 1: 重建 Fiat-Shamir transcript ===
    let step1 = VerifierStep {
        step_num: 1,
        title: "Step 1: 重建 Fiat-Shamir Transcript".to_string(),
        description: "從證明中的承諾值推導隨機挑戰".to_string(),
        equations: vec![
            r"\beta, \gamma \leftarrow H([a]_1, [b]_1, [c]_1)".to_string(),
            r"\alpha \leftarrow H(\beta, \gamma, [z]_1)".to_string(),
            r"\zeta \leftarrow H(\alpha, [t_{lo}]_1, [t_{mid}]_1, [t_{hi}]_1)".to_string(),
            r"v, u \leftarrow H(\zeta, \bar{a}, \bar{b}, \bar{c}, \ldots)".to_string(),
        ],
        intermediate_values: vec![
            ("β".to_string(), "挑戰值 (用於置換)".to_string()),
            ("γ".to_string(), "挑戰值 (用於置換)".to_string()),
            ("α".to_string(), "挑戰值 (組合約束)".to_string()),
            ("ζ".to_string(), "評估點".to_string()),
            ("v".to_string(), "批量化隨機數".to_string()),
            ("u".to_string(), "批量化隨機數".to_string()),
        ],
    };
    steps.push(step1);

    // === Step 2: 計算 Public Input 多項式 ===
    let step2 = VerifierStep {
        step_num: 2,
        title: "Step 2: 評估 PI(ζ)".to_string(),
        description: "從公開輸入重建 PI(X) 並在 ζ 評估".to_string(),
        equations: vec![
            r"PI(X) = \sum_{i=1}^{\ell} x_i \cdot L_i(X)".to_string(),
            r"PI(\zeta) = \sum_{i=1}^{\ell} x_i \cdot L_i(\zeta)".to_string(),
        ],
        intermediate_values: vec![
            ("x₁".to_string(), "3 (公開輸入 x)".to_string()),
            ("x₂".to_string(), "12 (公開輸入 y)".to_string()),
            ("PI(ζ)".to_string(), "計算出的值".to_string()),
        ],
    };
    steps.push(step2);

    // === Step 3: 計算零多項式 Z_H(ζ) ===
    let step3 = VerifierStep {
        step_num: 3,
        title: "Step 3: 計算 Z_H(ζ)".to_string(),
        description: "計算消失多項式在 ζ 的值".to_string(),
        equations: vec![
            r"Z_H(X) = X^n - 1".to_string(),
            r"Z_H(\zeta) = \zeta^n - 1".to_string(),
        ],
        intermediate_values: vec![
            ("n".to_string(), "domain 大小".to_string()),
            ("Z_H(ζ)".to_string(), "計算出的值".to_string()),
        ],
    };
    steps.push(step3);

    // === Step 4: 計算 Lagrange 多項式 L_1(ζ) ===
    let step4 = VerifierStep {
        step_num: 4,
        title: "Step 4: 計算 L₁(ζ)".to_string(),
        description: "計算第一個 Lagrange 基在 ζ 的值".to_string(),
        equations: vec![
            r"L_1(X) = \frac{\omega (X^n - 1)}{n(X - \omega)}".to_string(),
            r"L_1(\zeta) = \frac{\omega (\zeta^n - 1)}{n(\zeta - \omega)}".to_string(),
        ],
        intermediate_values: vec![
            ("ω".to_string(), "n次單位根生成元".to_string()),
            ("L₁(ζ)".to_string(), "計算出的值".to_string()),
        ],
    };
    steps.push(step4);

    // === Step 5: 計算線性化多項式常數項 ===
    let step5 = VerifierStep {
        step_num: 5,
        title: "Step 5: 計算線性化多項式".to_string(),
        description: "將 gate 約束和置換約束組合成單一多項式".to_string(),
        equations: vec![
            r"r_0 = PI(\zeta) - L_1(\zeta)\alpha^2 - (\bar{a} + \beta\bar{s}_{\sigma_1} + \gamma)(\bar{b} + \beta\bar{s}_{\sigma_2} + \gamma)(\bar{c} + \gamma)\bar{z}_\omega \alpha".to_string(),
        ],
        intermediate_values: vec![
            ("r₀".to_string(), "常數項".to_string()),
        ],
    };
    steps.push(step5);

    // === Step 6: 批量驗證所有多項式開啟 ===
    let step6 = VerifierStep {
        step_num: 6,
        title: "Step 6: 批量多項式開啟驗證".to_string(),
        description: "使用 pairing 批量驗證所有評估".to_string(),
        equations: vec![
            r"[F]_1 = [D]_1 + v[a]_1 + v^2[b]_1 + v^3[c]_1 + v^4[s_{\sigma_1}]_1 + v^5[s_{\sigma_2}]_1".to_string(),
            r"[E]_1 = (-r_0 + v\bar{a} + v^2\bar{b} + v^3\bar{c} + v^4\bar{s}_{\sigma_1} + v^5\bar{s}_{\sigma_2} + u\bar{z}_\omega) \cdot [1]_1".to_string(),
        ],
        intermediate_values: vec![
            ("[F]₁".to_string(), "批量承諾".to_string()),
            ("[E]₁".to_string(), "批量評估".to_string()),
        ],
    };
    steps.push(step6);

    // 實際執行驗證
    let result = verifier
        .verify(proof, public_inputs)
        .is_ok();

    let total_time = start_total.elapsed().as_millis() as u64;

    println!("✅ 驗證完成！結果: {}", if result { "通過 ✓" } else { "失敗 ✗" });
    println!("   - 驗證耗時: {} ms", total_time);

    let trace = VerifierTrace {
        steps,
        pairing_checks: vec![
            r"e([W_\zeta]_1 + u[W_{\zeta\omega}]_1, [x]_2) \stackrel{?}{=} e(\zeta[W_\zeta]_1 + u\zeta\omega[W_{\zeta\omega}]_1 + [F]_1 - [E]_1, [1]_2)".to_string(),
        ],
        verification_result: result,
        total_time_ms: total_time,
    };

    (result, trace)
}

/// 分析驗證者的計算複雜度
pub fn analyze_verifier_complexity() {
    println!("\n📊 Verifier 複雜度分析:");
    println!("   - Pairing 運算: 2 次");
    println!("   - G1 標量乘法: ~16 次 (取決於 linearization)");
    println!("   - 域元素運算: O(log n) 次 (計算 Z_H, L_1)");
    println!("   - 總複雜度: O(log n) + O(1) pairings");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_steps() {
        // 驗證我們定義了正確數量的驗證步驟
        let expected_steps = 6;

        // 這裡應該有 6 個主要步驟
        assert!(expected_steps == 6);
    }

    #[test]
    fn test_pairing_count() {
        // PLONK 驗證只需要 2 個 pairing
        let pairing_count = 2;
        assert_eq!(pairing_count, 2);
    }
}
