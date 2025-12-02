// backend/src/types.rs
// 定義所有用於 JSON 輸出的資料結構

use serde::Serialize;

/// Setup 階段的統計資料
#[derive(Serialize)]
pub struct SetupMetrics {
    pub n: u64,                    // domain 大小
    pub d: u64,                    // 多項式最高次數
    pub num_g1: u64,               // G1 元素數量
    pub num_g2: u64,               // G2 元素數量
    pub approx_size_bytes: u64,    // SRS 大約大小 (bytes)
    pub setup_time_ms: u64,        // Setup 耗時 (毫秒)
}

/// Preprocessing 階段的統計資料
#[derive(Serialize)]
pub struct PreprocessMetrics {
    pub num_gates: u64,            // gate 數量
    pub n_domain: u64,             // FFT domain 大小
    pub num_public: u64,           // 公開輸入數量
    pub preprocess_time_ms: u64,   // 預處理耗時 (毫秒)

    // Selector 多項式承諾 (十六進位字串)
    pub q_l_commit_hex: String,
    pub q_r_commit_hex: String,
    pub q_m_commit_hex: String,
    pub q_o_commit_hex: String,
    pub q_c_commit_hex: String,

    // Permutation 多項式承諾
    pub s1_commit_hex: String,
    pub s2_commit_hex: String,
    pub s3_commit_hex: String,
}

/// Prover 單一回合的詳細資訊
#[derive(Serialize)]
pub struct ProverRoundDump {
    pub round_num: u32,                        // 回合編號
    pub name: String,                          // 回合名稱
    pub description: String,                   // 回合描述
    pub commitments: Vec<String>,              // 這回合產生的承諾
    pub challenges: Vec<(String, String)>,     // (challenge名稱, 值)
    pub evaluations: Vec<(String, String)>,    // (多項式名稱, 評估值)
    pub num_ffts: u64,                         // FFT 運算次數
    pub num_msms: u64,                         // Multi-scalar multiplication 次數
    pub elapsed_ms: u64,                       // 這回合耗時
}

/// Prover 完整的執行軌跡
#[derive(Serialize)]
pub struct ProverTrace {
    pub rounds: Vec<ProverRoundDump>,
    pub proof_bytes: u64,          // 最終證明大小
    pub total_time_ms: u64,        // 總耗時
}

/// Verifier 單一步驟的詳細資訊
#[derive(Serialize)]
pub struct VerifierStep {
    pub step_num: u32,                         // 步驟編號
    pub title: String,                         // 步驟標題
    pub description: String,                   // 步驟描述
    pub equations: Vec<String>,                // LaTeX 格式的方程式
    pub intermediate_values: Vec<(String, String)>, // (變數名, 值)
}

/// Verifier 完整的執行軌跡
#[derive(Serialize)]
pub struct VerifierTrace {
    pub steps: Vec<VerifierStep>,
    pub pairing_checks: Vec<String>,  // Pairing 檢查的方程式 (LaTeX)
    pub verification_result: bool,    // 驗證結果
    pub total_time_ms: u64,           // 總耗時
}

/// 電路的具體值 (用於展示)
#[derive(Serialize)]
pub struct CircuitWitness {
    pub w: String,     // witness w 的值
    pub x: String,     // 公開輸入 x
    pub y: String,     // 公開輸入 y
    pub t: String,     // 中間變數 t = w²
}

/// Gate 的詳細資訊
#[derive(Serialize)]
pub struct GateInfo {
    pub gate_id: u32,
    pub gate_type: String,     // "multiplication" 或 "addition"
    pub constraint: String,    // 約束方程式 (LaTeX)
    pub a: String,             // 左輸入
    pub b: String,             // 右輸入
    pub c: String,             // 輸出
    pub q_l: String,           // selector 值
    pub q_r: String,
    pub q_o: String,
    pub q_m: String,
    pub q_c: String,
}

/// 完整的電路資訊
#[derive(Serialize)]
pub struct CircuitInfo {
    pub description: String,
    pub witness: CircuitWitness,
    pub gates: Vec<GateInfo>,
}
