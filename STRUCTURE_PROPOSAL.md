# 🎓 密碼學技術學習網站 - 結構規劃

## 📁 建議的目錄結構

```
crypto-research/  (或改名為 research-notes)
│
├── index.html                          # 🏠 主索引頁面（技術導航中心）
├── README.md                           # 專案說明
├── assets/                             # 共用資源
│   ├── css/
│   │   └── common.css                  # 統一樣式
│   ├── js/
│   │   └── navigation.js               # 導航功能
│   └── images/
│       └── logos/                      # 各技術 logo
│
├── plonk/                              # ✅ PLONK 技術報告
│   ├── index.html                      # 當前的 PLONK 詳細報告
│   ├── demo.html                       # PLONK Demo
│   ├── backend/                        # Rust 實作
│   ├── web/                            # 前端資源
│   └── README.md                       # PLONK 專用說明
│
├── groth16/                            # 🔮 未來：Groth16 技術報告
│   ├── index.html
│   ├── demo.html
│   └── README.md
│
├── stark/                              # 🔮 未來：STARK 技術報告
│   ├── index.html
│   └── README.md
│
├── fhe/                                # 🔮 未來：全同態加密
│   ├── index.html
│   └── README.md
│
└── mpc/                                # 🔮 未來：多方安全計算
    ├── index.html
    └── README.md
```

---

## 🎨 主索引頁面 (index.html) 設計建議

### **視覺風格**
- **導航卡片式設計**：每個技術一張卡片，包含：
  - 技術名稱 + Logo
  - 簡短描述（2-3 行）
  - 研究進度標籤（如：✅ 完成、🚧 進行中、📝 規劃中）
  - 難度標籤（入門 / 進階 / 專家）
  - 最後更新日期

### **主要區塊**
1. **Hero Section（頂部橫幅）**
   - 標題：「密碼學技術學習筆記」
   - 副標題：「研究所期間的論文整理與實作」
   - 統計：已完成 X 篇報告、累計 Y 字、代碼 Z 行

2. **技術分類導航**
   - **零知識證明系列**：PLONK, Groth16, STARK, Bulletproofs
   - **同態加密系列**：FHE, TFHE, Lattice-based
   - **多方計算系列**：MPC, Secret Sharing
   - **其他**：Merkle Trees, Commitment Schemes, etc.

3. **時間軸（Timeline）**
   - 按研究時間順序展示

4. **標籤過濾**
   - 可按難度、完成度、技術類型篩選

---

## 🔄 遷移步驟（從現有專案轉換）

### **步驟 1：重命名專案**
```bash
# 選項 A：直接在 GitHub 上重命名 repository
# Settings > Repository name > crypto-research

# 選項 B：本地處理
cd ..
mv PLONK crypto-research
cd crypto-research
```

### **步驟 2：建立新的主索引頁**
```bash
# 備份當前 index.html
mv index.html plonk_report.html

# 創建 plonk/ 子目錄
mkdir plonk

# 移動 PLONK 相關文件
mv plonk_report.html plonk/index.html
mv demo.html plonk/
mv backend plonk/
mv web plonk/

# 創建新的主索引頁（稍後提供模板）
# touch index.html
```

### **步驟 3：建立共用資源**
```bash
mkdir -p assets/{css,js,images}
```

### **步驟 4：更新 README.md**
- 改為整體專案介紹
- 列出所有技術報告的索引

### **步驟 5：更新 GitHub Pages 設定**
- Settings > Pages > Source: main branch / root
- 確保新的 index.html 成為首頁

---

## 📝 模板示例

### **主索引頁 HTML 結構建議**

```html
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>密碼學技術研究筆記</title>
    <link rel="stylesheet" href="assets/css/common.css">
</head>
<body>
    <header>
        <h1>🔐 密碼學技術研究筆記</h1>
        <p>研究所期間的論文整理、中文報告與實作</p>
    </header>

    <nav class="filter-bar">
        <button data-filter="all">全部</button>
        <button data-filter="zk">零知識證明</button>
        <button data-filter="fhe">同態加密</button>
        <button data-filter="mpc">多方計算</button>
    </nav>

    <main class="tech-grid">
        <!-- PLONK Card -->
        <article class="tech-card" data-category="zk" data-status="completed">
            <div class="card-header">
                <h2>PLONK</h2>
                <span class="badge completed">✅ 完成</span>
            </div>
            <p class="description">
                Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge
            </p>
            <div class="meta">
                <span class="difficulty">🔴 進階</span>
                <span class="date">2025-12-01</span>
            </div>
            <div class="actions">
                <a href="plonk/index.html" class="btn-primary">查看報告</a>
                <a href="plonk/demo.html" class="btn-secondary">互動 Demo</a>
            </div>
        </article>

        <!-- Future: Groth16 Card -->
        <article class="tech-card" data-category="zk" data-status="planned">
            <div class="card-header">
                <h2>Groth16</h2>
                <span class="badge planned">📝 規劃中</span>
            </div>
            <p class="description">
                更小的 proof size，但需要 circuit-specific setup
            </p>
            <div class="meta">
                <span class="difficulty">🟡 中階</span>
                <span class="date">TBD</span>
            </div>
        </article>

        <!-- 更多技術卡片... -->
    </main>

    <footer>
        <p>© 2025 高璿程 | <a href="https://github.com/xuancheng307">GitHub</a></p>
    </footer>

    <script src="assets/js/navigation.js"></script>
</body>
</html>
```

---

## 🎯 未來擴展流程（添加新技術）

每當您研究完一篇新論文，只需：

1. **創建新目錄**：
   ```bash
   mkdir new-tech
   cd new-tech
   ```

2. **複製 PLONK 模板**：
   ```bash
   cp ../plonk/index.html ./
   # 修改內容
   ```

3. **更新主索引頁**：
   - 在 `index.html` 添加新的 tech-card

4. **提交到 GitHub**：
   ```bash
   git add .
   git commit -m "新增 [技術名稱] 報告"
   git push
   ```

---

## ✅ 優勢

1. **模塊化**：每個技術獨立維護，互不干擾
2. **可擴展**：輕鬆添加新技術報告
3. **統一風格**：共用 CSS 確保視覺一致
4. **易於導航**：主頁作為技術地圖
5. **SEO 友好**：清晰的 URL 結構（如 `/plonk/`, `/groth16/`）
6. **展示友好**：適合作為作品集展示

---

## 🚀 下一步行動

1. **決定是否重命名專案**（PLONK → crypto-research）
2. **創建主索引頁**（我可以幫您生成完整的 HTML/CSS/JS）
3. **遷移 PLONK 文件到子目錄**
4. **更新 GitHub 設定**
5. **測試並部署**

---

**您希望我現在就幫您：**
- ✅ 生成主索引頁的完整代碼？
- ✅ 執行文件遷移操作？
- ✅ 還是先看看這個結構規劃是否符合需求？
