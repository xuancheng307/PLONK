// backend/src/main.rs
// PLONK Demo 主程式：完整跑通 Setup → Prove → Verify

mod types;
mod srs;
mod circuit;
mod prover;
mod verifier;

use std::fs::{self, File};
use std::io::Write;
use serde_json::to_string_pretty;
use dusk_plonk::prelude::*;

fn main() {
    println!("╔═══════════════════════════════════════════════╗");
    println!("║     PLONK Demo: w² + x = y                   ║");
    println!("║     證明 w=3 使得 3² + 3 = 12                ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    // 確保輸出目錄存在
    fs::create_dir_all("../web/data").expect("❌ 無法創建 data 目錄");

    // ========================================
    // 第 6 章：Universal Setup
    // ========================================
    println!("\n━━━ 第 6 章：Universal Setup ━━━");
    let (pub_params, setup_metrics) = srs::run_setup(1 << 4); // n = 16
    write_json("../web/data/setup_metrics.json", &setup_metrics);

    // ========================================
    // 第 7 章：Circuit & Preprocessing
    // ========================================
    println!("\n━━━ 第 7 章：電路與預處理 ━━━");
    let (prover, verifier, preprocess_metrics, circuit_info) =
        circuit::build_and_preprocess(&pub_params);

    write_json("../web/data/preprocess_metrics.json", &preprocess_metrics);
    write_json("../web/data/circuit_info.json", &circuit_info);

    // ========================================
    // 第 8 章：Prover (5 rounds)
    // ========================================
    println!("\n━━━ 第 8 章：Prover 證明生成 ━━━");
    let (proof, prover_trace) = prover::prove_with_trace(&prover);

    // 計算複雜度
    prover::compute_prover_complexity(&prover_trace);

    write_json("../web/data/prover_trace.json", &prover_trace);

    // ========================================
    // 第 9 章：Verifier
    // ========================================
    println!("\n━━━ 第 9 章：Verifier 驗證 ━━━");

    // 公開輸入: x=3, y=12
    let public_inputs = vec![
        BlsScalar::from(3u64),   // x
        BlsScalar::from(12u64),  // y
    ];

    let (ok, verifier_trace) = verifier::verify_with_trace(
        &verifier,
        &proof,
        &public_inputs,
    );

    // 分析複雜度
    verifier::analyze_verifier_complexity();

    write_json("../web/data/verifier_trace.json", &verifier_trace);

    // ========================================
    // 總結
    // ========================================
    println!("\n╔═══════════════════════════════════════════════╗");
    if ok {
        println!("║  ✅ 驗證成功！證明有效！                       ║");
    } else {
        println!("║  ❌ 驗證失敗！證明無效！                       ║");
    }
    println!("╚═══════════════════════════════════════════════╝");

    println!("\n📁 所有數據已輸出到 web/data/");
    println!("   - setup_metrics.json");
    println!("   - preprocess_metrics.json");
    println!("   - circuit_info.json");
    println!("   - prover_trace.json");
    println!("   - verifier_trace.json");

    println!("\n💡 下一步：");
    println!("   1. 開啟 web/index.html 查看報告");
    println!("   2. Demo 區塊會自動載入這些 JSON 數據");
    println!("   3. 查看完整的 PLONK 流程展示\n");

    // 寫入一個簡單的摘要檔案
    write_summary(&setup_metrics, &prover_trace, &verifier_trace, ok);
}

/// 輸出 JSON 檔案的輔助函數
fn write_json<T: serde::Serialize>(path: &str, value: &T) {
    let json_str = to_string_pretty(value)
        .expect("❌ JSON 序列化失敗");

    let mut file = File::create(path)
        .expect(&format!("❌ 無法創建檔案: {}", path));

    file.write_all(json_str.as_bytes())
        .expect(&format!("❌ 無法寫入檔案: {}", path));

    println!("   ✓ 已寫入: {}", path);
}

/// 寫入執行摘要
fn write_summary(
    setup: &types::SetupMetrics,
    prover: &types::ProverTrace,
    verifier: &types::VerifierTrace,
    verified: bool,
) {
    use std::io::BufWriter;

    let summary = format!(
        r#"
═══════════════════════════════════════════════
PLONK Demo 執行摘要
═══════════════════════════════════════════════

電路：w² + x = y
實例：w=3, x=3, y=12
驗證：3² + 3 = 9 + 3 = 12 ✓

───────────────────────────────────────────────
Setup 階段
───────────────────────────────────────────────
Domain 大小 (n):        {}
SRS G1 元素數:          {}
SRS G2 元素數:          {}
SRS 總大小:             {:.2} KB
Setup 耗時:             {} ms

───────────────────────────────────────────────
Prover 階段
───────────────────────────────────────────────
證明大小:               {} bytes
總 FFT 次數:            {}
總 MSM 次數:            {}
證明生成耗時:           {} ms

回合詳情:
{}

───────────────────────────────────────────────
Verifier 階段
───────────────────────────────────────────────
驗證步驟數:             {}
Pairing 檢查:           {}
驗證耗時:               {} ms
驗證結果:               {}

═══════════════════════════════════════════════
生成時間: {}
═══════════════════════════════════════════════
"#,
        setup.n,
        setup.num_g1,
        setup.num_g2,
        setup.approx_size_bytes as f64 / 1024.0,
        setup.setup_time_ms,
        prover.proof_bytes,
        prover.rounds.iter().map(|r| r.num_ffts).sum::<u64>(),
        prover.rounds.iter().map(|r| r.num_msms).sum::<u64>(),
        prover.total_time_ms,
        prover
            .rounds
            .iter()
            .map(|r| format!("  Round {}: {} ({} ms)", r.round_num, r.name, r.elapsed_ms))
            .collect::<Vec<_>>()
            .join("\n"),
        verifier.steps.len(),
        verifier.pairing_checks.len(),
        verifier.total_time_ms,
        if verified { "✅ 通過" } else { "❌ 失敗" },
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
    );

    let file = File::create("../web/data/summary.txt")
        .expect("❌ 無法創建摘要檔案");

    let mut writer = BufWriter::new(file);
    writer
        .write_all(summary.as_bytes())
        .expect("❌ 無法寫入摘要");

    println!("   ✓ 已寫入: ../web/data/summary.txt");
}
