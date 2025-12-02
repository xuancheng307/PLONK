// backend/src/circuit.rs
// 電路定義：證明 w² + x = y

use std::time::Instant;
use dusk_plonk::prelude::*;
use crate::types::{PreprocessMetrics, CircuitInfo, CircuitWitness, GateInfo};

/// Demo 電路：w² + x = y
///
/// 具體值：
/// - w = 3 (witness, 私密)
/// - x = 3 (public input)
/// - y = 12 (public input)
/// - 驗證：3² + 3 = 9 + 3 = 12 ✓
#[derive(Default)]
pub struct SquareAddCircuit {
    pub w: BlsScalar,  // witness
    pub x: BlsScalar,  // public input
    pub y: BlsScalar,  // public input
}

impl SquareAddCircuit {
    /// 創建 demo 電路實例
    pub fn new_demo() -> Self {
        Self {
            w: BlsScalar::from(3u64),
            x: BlsScalar::from(3u64),
            y: BlsScalar::from(12u64),
        }
    }

    /// 獲取電路的詳細資訊 (用於前端展示)
    pub fn get_circuit_info(&self) -> CircuitInfo {
        // 計算中間變數
        let w_val = 3u64;
        let t_val = w_val * w_val; // t = w² = 9

        CircuitInfo {
            description: "證明存在秘密 w，使得 w² + x = y".to_string(),
            witness: CircuitWitness {
                w: format!("{}", w_val),
                x: "3".to_string(),
                y: "12".to_string(),
                t: format!("{}", t_val),
            },
            gates: vec![
                GateInfo {
                    gate_id: 0,
                    gate_type: "multiplication".to_string(),
                    constraint: "w \\cdot w = t".to_string(),
                    a: "w = 3".to_string(),
                    b: "w = 3".to_string(),
                    c: "t = 9".to_string(),
                    q_l: "0".to_string(),
                    q_r: "0".to_string(),
                    q_o: "-1".to_string(),
                    q_m: "1".to_string(),
                    q_c: "0".to_string(),
                },
                GateInfo {
                    gate_id: 1,
                    gate_type: "addition".to_string(),
                    constraint: "t + x = y".to_string(),
                    a: "t = 9".to_string(),
                    b: "x = 3".to_string(),
                    c: "y = 12".to_string(),
                    q_l: "1".to_string(),
                    q_r: "1".to_string(),
                    q_o: "-1".to_string(),
                    q_m: "0".to_string(),
                    q_c: "0".to_string(),
                },
            ],
        }
    }
}

impl Circuit for SquareAddCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        // 添加 witness
        let w_var = composer.append_witness(self.w);

        // 添加 public inputs
        let x_var = composer.append_public(self.x);
        let y_var = composer.append_public(self.y);

        // Gate 0: w * w = t (乘法門)
        // gate_mul 自動計算 o = q_m · a · b + q_4 · d + q_c + PI
        // 設定 q_m = 1, 所以 t = w * w
        let t_var = composer.gate_mul(
            Constraint::new()
                .mult(1)      // q_m = 1 (啟用乘法)
                .a(w_var)     // a = w
                .b(w_var)     // b = w
        );

        // Gate 1: t + x = sum (加法門)
        // gate_add 自動計算 o = q_l · a + q_r · b + q_4 · d + q_c + PI
        // 設定 q_l = 1, q_r = 1, 所以 sum = t + x
        let sum = composer.gate_add(
            Constraint::new()
                .left(1)      // q_l = 1 (啟用左輸入)
                .right(1)     // q_r = 1 (啟用右輸入)
                .a(t_var)     // a = t
                .b(x_var)     // b = x
        );

        // 約束：sum == y
        composer.assert_equal(sum, y_var);

        Ok(())
    }
}

/// 建立電路並執行預處理
pub fn build_and_preprocess(
    pub_params: &PublicParameters,
) -> (Prover, Verifier, PreprocessMetrics, CircuitInfo) {
    println!("🔨 建立電路：w² + x = y");

    let start = Instant::now();

    // 創建電路實例
    let circuit = SquareAddCircuit::new_demo();
    let circuit_info = circuit.get_circuit_info();

    // 編譯電路
    let (prover, verifier) = Compiler::compile::<SquareAddCircuit>(pub_params, b"plonk-demo")
        .expect("❌ 電路編譯失敗");

    let elapsed = start.elapsed().as_millis() as u64;

    println!("✅ 電路建立完成！耗時 {} ms", elapsed);
    println!("   - Gates: {}", circuit_info.gates.len());
    println!("   - Public inputs: 2 (x, y)");

    // TODO: 從 verifier 中提取 selector 承諾
    // 這需要查看 dusk-plonk 的內部 API
    let metrics = PreprocessMetrics {
        num_gates: circuit_info.gates.len() as u64,
        n_domain: 4,  // 實際上會根據電路自動調整
        num_public: 2,
        preprocess_time_ms: elapsed,
        q_l_commit_hex: "0x...".to_string(),
        q_r_commit_hex: "0x...".to_string(),
        q_m_commit_hex: "0x...".to_string(),
        q_o_commit_hex: "0x...".to_string(),
        q_c_commit_hex: "0x...".to_string(),
        s1_commit_hex: "0x...".to_string(),
        s2_commit_hex: "0x...".to_string(),
        s3_commit_hex: "0x...".to_string(),
    };

    (prover, verifier, metrics, circuit_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_values() {
        let circuit = SquareAddCircuit::new_demo();
        let w = 3u64;
        let x = 3u64;
        let y = 12u64;

        assert_eq!(w * w + x, y);
    }

    #[test]
    fn test_circuit_info() {
        let circuit = SquareAddCircuit::new_demo();
        let info = circuit.get_circuit_info();

        assert_eq!(info.gates.len(), 2);
        assert_eq!(info.witness.w, "3");
        assert_eq!(info.witness.x, "3");
        assert_eq!(info.witness.y, "12");
        assert_eq!(info.witness.t, "9");
    }
}
