// web/demo.js
// 載入 backend 產生的 JSON 數據並展示

// ===================================
// 載入 Setup 數據
// ===================================
async function loadSetup() {
    try {
        const res = await fetch('web/data/setup_metrics.json');
        const data = await res.json();

        const html = `
            <div class="demo-box">
                <h4>📊 Setup 統計</h4>
                <table class="metrics-table">
                    <tr><th>Domain 大小 (n)</th><td>${data.n}</td></tr>
                    <tr><th>多項式最高次數 (d)</th><td>${data.d}</td></tr>
                    <tr><th>G₁ 元素數</th><td>${data.num_g1}</td></tr>
                    <tr><th>G₂ 元素數</th><td>${data.num_g2}</td></tr>
                    <tr><th>SRS 大小</th><td>${(data.approx_size_bytes / 1024).toFixed(2)} KB</td></tr>
                    <tr><th>Setup 耗時</th><td><strong>${data.setup_time_ms} ms</strong></td></tr>
                </table>
                <p class="demo-note">
                    💡 Universal Setup 只需執行一次，可重複用於所有相同大小的電路
                </p>
            </div>
        `;

        document.getElementById('setup-demo').innerHTML = html;
    } catch (err) {
        console.error('載入 Setup 數據失敗:', err);
        document.getElementById('setup-demo').innerHTML =
            '<p class="error">⚠️ 尚未生成數據，請先執行 backend</p>';
    }
}

// ===================================
// 載入電路資訊
// ===================================
async function loadCircuit() {
    try {
        const res = await fetch('web/data/circuit_info.json');
        const data = await res.json();

        let gatesHTML = data.gates.map(gate => `
            <div class="gate-card">
                <h5>Gate ${gate.gate_id}: ${gate.gate_type}</h5>
                <p><strong>約束：</strong> \\(${gate.constraint}\\)</p>
                <table class="gate-table">
                    <tr><th>Wire a</th><td>${gate.a}</td></tr>
                    <tr><th>Wire b</th><td>${gate.b}</td></tr>
                    <tr><th>Wire c</th><td>${gate.c}</td></tr>
                </table>
                <table class="selector-table">
                    <tr>
                        <th>q<sub>L</sub></th>
                        <th>q<sub>R</sub></th>
                        <th>q<sub>O</sub></th>
                        <th>q<sub>M</sub></th>
                        <th>q<sub>C</sub></th>
                    </tr>
                    <tr>
                        <td>${gate.q_l}</td>
                        <td>${gate.q_r}</td>
                        <td>${gate.q_o}</td>
                        <td>${gate.q_m}</td>
                        <td>${gate.q_c}</td>
                    </tr>
                </table>
            </div>
        `).join('');

        const html = `
            <div class="demo-box">
                <h4>🔧 電路說明</h4>
                <p>${data.description}</p>

                <h5>Witness & Public Inputs:</h5>
                <table class="witness-table">
                    <tr><th>變數</th><th>值</th><th>類型</th></tr>
                    <tr><td>w</td><td>${data.witness.w}</td><td>🔒 Private (witness)</td></tr>
                    <tr><td>x</td><td>${data.witness.x}</td><td>🔓 Public input</td></tr>
                    <tr><td>y</td><td>${data.witness.y}</td><td>🔓 Public input</td></tr>
                    <tr><td>t (= w²)</td><td>${data.witness.t}</td><td>🔸 Intermediate</td></tr>
                </table>

                <h5>Gates 詳情:</h5>
                ${gatesHTML}
            </div>
        `;

        document.getElementById('circuit-demo').innerHTML = html;

        // 重新渲染 MathJax (如果有使用的話)
        if (window.MathJax) {
            MathJax.typesetPromise();
        }
    } catch (err) {
        console.error('載入電路數據失敗:', err);
    }
}

// ===================================
// 載入 Prover 軌跡
// ===================================
async function loadProver() {
    try {
        const res = await fetch('web/data/prover_trace.json');
        const data = await res.json();

        const totalFFTs = data.rounds.reduce((sum, r) => sum + r.num_ffts, 0);
        const totalMSMs = data.rounds.reduce((sum, r) => sum + r.num_msms, 0);

        let roundsHTML = data.rounds.map(round => `
            <div class="round-card">
                <h5>${round.name}</h5>
                <p>${round.description}</p>

                ${round.commitments.length > 0 ? `
                    <p><strong>承諾:</strong> ${round.commitments.join(', ')}</p>
                ` : ''}

                ${round.challenges.length > 0 ? `
                    <p><strong>挑戰:</strong> ${round.challenges.map(c => c[0]).join(', ')}</p>
                ` : ''}

                ${round.evaluations.length > 0 ? `
                    <p><strong>評估:</strong> ${round.evaluations.map(e => e[0]).join(', ')}</p>
                ` : ''}

                <div class="metrics-row">
                    <span>FFT: ${round.num_ffts}</span>
                    <span>MSM: ${round.num_msms}</span>
                    <span>⏱️ ${round.elapsed_ms} ms</span>
                </div>
            </div>
        `).join('');

        const html = `
            <div class="demo-box">
                <h4>🔐 Prover 證明生成</h4>

                <div class="summary-box">
                    <p><strong>總耗時:</strong> ${data.total_time_ms} ms</p>
                    <p><strong>證明大小:</strong> ${data.proof_bytes} bytes</p>
                    <p><strong>總 FFT 次數:</strong> ${totalFFTs}</p>
                    <p><strong>總 MSM 次數:</strong> ${totalMSMs}</p>
                </div>

                <h5>5 Rounds 詳情:</h5>
                ${roundsHTML}
            </div>
        `;

        document.getElementById('prover-demo').innerHTML = html;
    } catch (err) {
        console.error('載入 Prover 數據失敗:', err);
    }
}

// ===================================
// 載入 Verifier 軌跡
// ===================================
async function loadVerifier() {
    try {
        const res = await fetch('web/data/verifier_trace.json');
        const data = await res.json();

        let stepsHTML = data.steps.map(step => `
            <div class="step-card">
                <h5>Step ${step.step_num}: ${step.title}</h5>
                <p>${step.description}</p>

                ${step.equations.length > 0 ? `
                    <div class="equations">
                        ${step.equations.map(eq => `<p>\\(${eq}\\)</p>`).join('')}
                    </div>
                ` : ''}

                ${step.intermediate_values.length > 0 ? `
                    <details>
                        <summary>中間值</summary>
                        <ul>
                            ${step.intermediate_values.map(v =>
                                `<li><strong>${v[0]}:</strong> ${v[1]}</li>`
                            ).join('')}
                        </ul>
                    </details>
                ` : ''}
            </div>
        `).join('');

        const html = `
            <div class="demo-box">
                <h4>🔍 Verifier 驗證流程</h4>

                <div class="summary-box ${data.verification_result ? 'success' : 'failure'}">
                    <p><strong>驗證結果:</strong> ${data.verification_result ? '✅ 通過' : '❌ 失敗'}</p>
                    <p><strong>驗證耗時:</strong> ${data.total_time_ms} ms</p>
                    <p><strong>驗證步驟:</strong> ${data.steps.length} 步</p>
                </div>

                ${stepsHTML}

                <div class="pairing-check">
                    <h5>🔗 Pairing 檢查</h5>
                    ${data.pairing_checks.map(eq => `<p>\\(${eq}\\)</p>`).join('')}
                </div>
            </div>
        `;

        document.getElementById('verifier-demo').innerHTML = html;

        // 重新渲染 MathJax
        if (window.MathJax) {
            MathJax.typesetPromise();
        }
    } catch (err) {
        console.error('載入 Verifier 數據失敗:', err);
    }
}

// ===================================
// 初始化所有 Demo
// ===================================
async function initAllDemos() {
    console.log('🚀 載入 PLONK Demo 數據...');

    await Promise.all([
        loadSetup(),
        loadCircuit(),
        loadProver(),
        loadVerifier(),
    ]);

    console.log('✅ Demo 數據載入完成！');
}

// 頁面載入完成後執行
window.addEventListener('DOMContentLoaded', initAllDemos);
