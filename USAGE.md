# ccxt_safe — CCXT 安全封装使用指南

## 问题

CCXT 在 28 个交易所实现中默认注入 broker/partner/referral 标识，将你的每笔交易归因到 CCXT 的返佣账户。这些注入全部 opt-out（默认开启），且无文档说明。

## 快速开始

```python
from ccxt_safe import create_safe_exchange, safe_create_order, enable_audit

# 1. 创建安全实例（自动清除所有 broker 注入）
exchange = create_safe_exchange('binance', apiKey='...', secret='...')

# 2. 启用审计 + 请求清洗（推荐：生产环境必开）
enable_audit(exchange, scrub=True)

# 3. 下单（自动生成无 broker 前缀的 clientOrderId）
order = safe_create_order(exchange, 'BTC/USDT', 'limit', 'buy', 0.001, 50000)
```

## SafetyPolicy — 策略化控制

```python
from ccxt_safe import SafetyPolicy, create_safe_exchange

# 默认：strict 模式（最强防护）
ex = create_safe_exchange('okx', apiKey='...', secret='...', password='...')

# 宽松模式（警告但不阻断）
p = SafetyPolicy(strict=False)  # audit_on_findings 自动降为 'warn'
ex = create_safe_exchange('okx', policy=p, apiKey='...', secret='...', password='...')
```

策略字段：

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `strict` | `True` | strict 模式下审计发现可疑字段会 raise |
| `allow_broker_opt_in` | `False` | 是否允许用户覆盖受保护的 broker key |
| `scrub_empty_fields` | `True` | 是否在 sign() 后清洗空值/已知默认值的 header/body |
| `block_onchain` | `True` | 是否阻止 Hyperliquid 链上授权交易 |
| `audit_on_findings` | `'raise'` | 审计发现时行为：`'raise'` 或 `'warn'` |

## 使用自己的 brokerId（显式 opt-in）

如果你有自己的返佣协议，想用自己的 brokerId 而非 CCXT 默认值：

```python
from ccxt_safe import SafetyPolicy, create_safe_exchange

p = SafetyPolicy(allow_broker_opt_in=True)
ex = create_safe_exchange('okx', policy=p,
                          apiKey='...', secret='...', password='...',
                          options={'brokerId': 'MY_OWN_BROKER_TAG'})
# ⚠ 注意：
# - 不能填 CCXT 默认值（如 '6b9ad766b55dBCDE'），会被拒绝
# - opt-in 会记录到日志，便于审计追溯
```

## 请求清洗器（Scrubber）

仅把 broker 值设为空字符串并不够——某些交易所/网关仍会将空 header 视为有效归因。
Scrubber 在 `sign()` 返回后执行最终清洗：

- 删除值为空或等于 CCXT 默认值的可疑 headers（KC-API-PARTNER、X-BM-BROKER-ID 等）
- 删除 JSON body 中的纯归因字段（tag、brokerId、referral_code 等，仅当值为空/已知默认值时）
- 保留 clientOrderId 类字段（不会破坏正常下单）

```python
# 启用审计 + 清洗（默认都开启）
enable_audit(exchange, scrub=True)

# 仅审计不清洗
enable_audit(exchange, scrub=False)

# dry-run 模式（阻止真实请求，用于验证）
enable_audit(exchange, dry_run=True, scrub=True)
```

## 为什么需要 `safe_create_order`

Binance 合约、OKX、Phemex 等在 `sign()` 中有硬编码 fallback，即使清空 `options` 仍会注入 broker 前缀到 `clientOrderId`。`safe_create_order()` 通过预填干净 UUID 阻止 fallback。

## CI 回归检测

```bash
# 首次运行：生成 baseline
python scan_ccxt_injection.py

# 后续运行（ccxt 升级后）：对比 baseline，新增注入点则 exit(1)
python scan_ccxt_injection.py

# 确认升级后刷新 baseline
python scan_ccxt_injection.py --refresh-baseline
```

升级 ccxt 推荐流程：
1. `pip install --upgrade ccxt`
2. `python scan_ccxt_injection.py` — 若 FAIL，检查新增注入点
3. 在 `ccxt_safe.py` 的 `SAFE_OVERRIDES` 中补充新交易所覆盖
4. 确认覆盖后：`python scan_ccxt_injection.py --refresh-baseline`
5. `python -m pytest tests/test_ccxt_safe.py` — 确保全绿

baseline key 使用 `filename|keyword|hash(snippet)` 格式，不依赖行号，升级时不会因行号漂移误报。

## 覆盖的交易所（28 个）

| 风险等级 | 交易所 | 注入方式 |
|---------|--------|---------|
| CRITICAL | hyperliquid | 链上 builder fee + referral 交易 |
| CRITICAL | kucoin, kucoinfutures | partner headers (签名认证) |
| HIGH | okx | brokerId → tag + clOrdId 前缀 |
| HIGH | binance | broker dict → newClientOrderId 前缀 |
| HIGH | bybit | brokerId → Referer header |
| HIGH | derive | referral_code (硬编码地址) |
| MEDIUM | bitget, bingx, bitmart, mexc, hashkey, coincatch, paradex | header 注入 |
| MEDIUM | bitmex, blofin, apex, cryptocom | body 字段注入 |
| MEDIUM | phemex, coinbase, coinbaseinternational, coinex, woo, woofipro, modetrade | clientOrderId 前缀 |
| MEDIUM | htx, bittrade | broker.id → client-order-id 前缀 |
| LOW | whitebit, tokocrypto | 有条件注入 |

## 文件清单

| 文件 | 用途 |
|------|------|
| `ccxt_safe.py` | 核心模块：SafetyPolicy、安全创建、scrubber、审计钩子、安全下单 |
| `tests/test_ccxt_safe.py` | 59 项测试（全部通过） |
| `scan_ccxt_injection.py` | CI 扫描脚本（稳定 baseline key） |
| `broker-scan-baseline.json` | 扫描基线（自动生成） |
