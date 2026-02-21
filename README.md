# anti_ccxt_broker

CCXT 隐藏抽佣防御工具包 — 自动检测、清除并审计 CCXT 在 29 个交易所中默认注入的 broker/partner/referral 归因标识。

## 问题背景

CCXT 在其 Python 实现中对 29 个交易所硬编码了 broker/partner/referral 标识注入。这些注入 **默认开启、无文档说明**，会将你的每笔交易静默归因到 CCXT 的返佣账户：

| 注入方式 | 影响交易所 | 风险 |
|---------|-----------|------|
| 链上 builder fee 授权 + referral 交易 | Hyperliquid | **CRITICAL** — 真实链上交易，授权第三方收费 |
| Partner headers（含 HMAC 签名认证） | KuCoin, KuCoinFutures | **CRITICAL** — 签名级绑定 |
| `clientOrderId` / `clOrdId` 前缀注入 | Binance, OKX, Phemex, Coinex, HTX, Bittrade, Coinbase, WhiteBit 等 | **HIGH** — 硬编码 fallback，清空 options 仍无法阻止 |
| HTTP Header 注入 | Bybit, Bitget, BingX, BitMart, MEXC, HashKey, Paradex, CoinCatch 等 | **MEDIUM** |
| Body 字段注入 | BitMEX, BloFin, Apex, Crypto.com, Woo, WoofiPro, ModeTrade | **MEDIUM** |
| 硬编码 referral 地址 | Derive | **HIGH** — 链上地址写死在源码中 |

**本工具包提供三层防御**：静态 options 覆盖 → 运行时请求清洗 → 方法级 clientOrderId 代理，确保零泄漏。

## 快速开始

### 安装

```bash
# 仅依赖 ccxt + Python 标准库，无额外依赖
pip install ccxt

# 克隆本仓库
git clone <repo-url> anti_ccxt_broker
```

### 30 秒接入（零改动策略代码）

**方式一：入口加一行**（推荐）

```python
# main.py（策略入口文件，只加这一行）
import ccxt_safe_bootstrap; ccxt_safe_bootstrap.enable()

# ---- 以下为原有策略代码，一行不改 ----
import ccxt
ex = ccxt.binance({'apiKey': '...', 'secret': '...'})
order = ex.create_order('BTC/USDT', 'limit', 'buy', 0.001, 50000)
# ✓ 所有 broker 注入已被自动清除
# ✓ create_order 自动补干净的 clientOrderId
# ✓ sign() 输出经过 scrubber 清洗
```

**方式二：sitecustomize 全自动**（连入口都不改）

```bash
# 将文件放到 PYTHONPATH 可见处
export PYTHONPATH=/path/to/anti_ccxt_broker:$PYTHONPATH
# Python 启动时自动 import sitecustomize.py → 调用 bootstrap()
python my_strategy.py   # 零改动
```

### 显式 API（需要改策略代码时）

```python
from ccxt_safe import create_safe_exchange, safe_create_order, enable_audit

# 创建安全实例
exchange = create_safe_exchange('binance', apiKey='...', secret='...')

# 启用审计 + 请求清洗
enable_audit(exchange, scrub=True)

# 安全下单（自动生成无 broker 前缀的 clientOrderId）
order = safe_create_order(exchange, 'BTC/USDT', 'limit', 'buy', 0.001, 50000)
```

## 工作原理

```
策略代码                     ccxt_safe_bootstrap                  ccxt_safe
─────────                   ──────────────────                  ─────────
import ccxt         ──→     (monkey-patched ccxt)
ccxt.binance({})    ──→     _SafeWrapper.__init__()
                              ├─ super().__init__()  (原始构造)
                              ├─ _apply_safety()
                              │   ├─ SAFE_OVERRIDES 覆盖      ←── 29 个交易所逐项配置
                              │   ├─ _patch_hyperliquid()      ←── 链上交易阻断
                              │   ├─ _verify_overrides()       ←── fail-closed 验证
                              │   ├─ _install_audit()
                              │   │   ├─ scrub sign() 输出     ←── 清洗 headers/body
                              │   │   └─ emit 结构化 JSON 证据
                              │   └─ _wrap_order_methods()
                              │       ├─ create_order  → 自动补 clean OID
                              │       ├─ create_orders → 批量补 clean OID
                              │       └─ edit_order    → 同上
                              └─ stamp _ccxt_safe_bootstrap=True

ex.create_order()   ──→     透明代理 → 注入干净 clientOrderId
                              └─ 原始 create_order()
                                  └─ sign() → audited_sign()
                                      ├─ scrub headers/body
                                      ├─ 扫描可疑字段
                                      └─ 输出审计证据
```

**关键设计**：

- **子类继承**：wrapper 是原始类的子类，`isinstance(ex, ccxt.Exchange)` 始终为 `True`
- **三层纵深防御**：options 覆盖 → sign() 清洗 → create_order() 代理
- **fail-closed**：构造后立即验证 options 是否生效，不一致则 raise
- **可逆**：`disable()` 一行恢复所有原始类

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CCXT_SAFE_ENABLE` | `1` | 主开关。`0` = 完全禁用 |
| `CCXT_SAFE_STRICT` | `1` | 严格模式。发现可疑字段时 raise |
| `CCXT_SAFE_DRY_RUN` | `0` | 干跑模式。阻止所有网络请求 |
| `CCXT_SAFE_AUDIT` | `raise` | 审计动作：`raise` 或 `warn` |
| `CCXT_SAFE_OPT_IN` | `0` | 允许用户自己的 brokerId（仍拒绝 CCXT 默认值） |
| `CCXT_SAFE_LOG` | *(stderr)* | 证据日志文件路径（JSON Lines 格式） |

**生产推荐**：

```bash
CCXT_SAFE_ENABLE=1
CCXT_SAFE_STRICT=1
CCXT_SAFE_AUDIT=raise
CCXT_SAFE_LOG=/var/log/ccxt_safe_audit.jsonl
```

## 覆盖的交易所（29 个）

| 风险等级 | 交易所 | 注入方式 |
|---------|--------|---------| 
| CRITICAL | hyperliquid | 链上 builder fee + referral 交易 |
| CRITICAL | kucoin, kucoinfutures | partner headers（签名认证） |
| HIGH | okx | brokerId → tag + clOrdId 前缀（hardcoded fallback） |
| HIGH | binance | broker dict → newClientOrderId 前缀（hardcoded fallback） |
| HIGH | bybit | brokerId → Referer header |
| HIGH | derive | referral_code（硬编码链上地址） |
| MEDIUM | bitget, bingx, bitmart, mexc, hashkey, coincatch, paradex | header 注入 |
| MEDIUM | bitmex, blofin, apex, cryptocom | body 字段注入 |
| MEDIUM | phemex, coinbase, coinbaseinternational, coinex, woo, woofipro, modetrade | clientOrderId 前缀 |
| MEDIUM | htx, bittrade | broker.id → client-order-id 前缀 |
| LOW | whitebit, tokocrypto | 有条件注入 |

## 验证

```bash
# 运行完整验证（dry-run 模式，无需真实 API key / 无网络请求）
python verify_no_injection.py

# 预期输出：
# ============================================================
# ccxt_safe_bootstrap — Injection Verification Suite
# ============================================================
# ...
# Results: 57/57 passed, 0 failed
# VERDICT: PASS — no injection detected, all safety measures active
```

```bash
# 运行单元测试
python -m pytest tests/test_ccxt_safe.py -v
```

```bash
# CI 扫描：检测 ccxt 源码中的注入点
python scan_ccxt_injection.py
```

## 回滚

```bash
# 方法 1：环境变量一键禁用
CCXT_SAFE_ENABLE=0 python my_strategy.py

# 方法 2：代码中禁用
import ccxt_safe_bootstrap
ccxt_safe_bootstrap.disable()   # 新实例恢复原始行为

# 方法 3：获取原始类（调试用）
OrigBinance = ccxt_safe_bootstrap.get_original_class('binance')
raw_ex = OrigBinance({'apiKey': '...', 'secret': '...'})
```

## 升级 ccxt

```bash
pip install --upgrade ccxt              # 1. 升级
python scan_ccxt_injection.py           # 2. 扫描 — FAIL 说明有新增注入
# 在 ccxt_safe.py SAFE_OVERRIDES 中补充   # 3. 覆盖新增交易所
python scan_ccxt_injection.py --refresh-baseline  # 4. 刷新 baseline
python -m pytest tests/test_ccxt_safe.py -v       # 5. 测试
python verify_no_injection.py                     # 6. 验证
```

Baseline 使用 `filename|keyword|sha1(snippet)` 格式的 key，不依赖行号，ccxt 升级改动行号时不会误报。

## 项目结构

```
anti_ccxt_broker/
├── ccxt_safe.py              # 核心模块：SafetyPolicy / SAFE_OVERRIDES / scrubber / 审计钩子
├── ccxt_safe_bootstrap.py    # 启动器：monkey-patch / 方法代理 / 环境变量配置
├── sitecustomize.py          # Mode A 自动启用（放 PYTHONPATH 即生效）
├── verify_no_injection.py    # 验证脚本（57 项 smoke test，覆盖 6 个关键交易所）
├── scan_ccxt_injection.py    # CI 扫描脚本（ccxt 源码注入点检测）
├── broker-scan-baseline.json # 扫描基线（自动生成）
├── tests/
│   └── test_ccxt_safe.py     # 单元测试
├── USAGE.md                  # 核心模块 API 使用指南
├── ZERO_CHANGE_GUIDE.md      # 零改动接入完整指南（含常见坑解析）
└── README.md                 # 本文件
```

## 详细文档

| 文档 | 内容 |
|------|------|
| [USAGE.md](USAGE.md) | 核心 API 使用指南：`create_safe_exchange` / `safe_create_order` / `enable_audit` / `SafetyPolicy` |
| [ZERO_CHANGE_GUIDE.md](ZERO_CHANGE_GUIDE.md) | 零改动接入完整指南：两种模式详解、生产配置、常见坑（Binance hardcoded defaultId / OKX clOrdId / Hyperliquid 链上授权等）、回滚方案、CI 集成 |

## 依赖

- Python >= 3.8
- ccxt（任意版本，已测试 4.x）
- 无其他外部依赖（仅使用 Python 标准库）

## 许可

MIT
