// backend/src/srs.rs
// 第 6 章：通用 Setup (Universal Setup)

use std::time::Instant;
use rand::thread_rng;
use dusk_plonk::prelude::*;
use crate::types::SetupMetrics;

/// 執行 Universal Setup，產生 SRS (Structured Reference String)
///
/// # 參數
/// - `n`: domain 大小 (必須是 2 的次方)
///
/// # 返回
/// - `PublicParameters`: 包含 commitment key 和 verifying key
/// - `SetupMetrics`: Setup 階段的統計資料
pub fn run_setup(n: usize) -> (PublicParameters, SetupMetrics) {
    println!("🔧 開始 Universal Setup (n = {})...", n);

    let d = n; // 多項式最高次數上界
    let start = Instant::now();

    // 使用 dusk-plonk 的 Setup API
    let mut rng = thread_rng();
    let pub_params = PublicParameters::setup(n, &mut rng)
        .expect("❌ Setup 失敗");

    let elapsed = start.elapsed().as_millis() as u64;

    // 計算 SRS 大小
    // BLS12-381: G1 compressed = 48 bytes, G2 compressed = 96 bytes
    let num_g1 = (d + 1) as u64;  // [1]₁, [x]₁, [x²]₁, ..., [xᵈ]₁
    let num_g2 = 2u64;              // [1]₂, [x]₂
    let approx_size_bytes = num_g1 * 48 + num_g2 * 96;

    println!("✅ Setup 完成！耗時 {} ms", elapsed);
    println!("   - G1 元素: {}", num_g1);
    println!("   - G2 元素: {}", num_g2);
    println!("   - 約略大小: {:.2} KB", approx_size_bytes as f64 / 1024.0);

    let metrics = SetupMetrics {
        n: n as u64,
        d: d as u64,
        num_g1,
        num_g2,
        approx_size_bytes,
        setup_time_ms: elapsed,
    };

    (pub_params, metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup() {
        let (pub_params, metrics) = run_setup(16);
        assert_eq!(metrics.n, 16);
        assert_eq!(metrics.num_g1, 17);
        assert_eq!(metrics.num_g2, 2);
    }
}
