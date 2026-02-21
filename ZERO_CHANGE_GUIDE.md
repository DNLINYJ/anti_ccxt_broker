# CCXT 安全封装 — 零改动接入指南

## 概述

CCXT 在 28+ 个交易所实现中默认注入 broker/partner/referral 标识，将你的每笔交易归因到 CCXT 的返佣账户。这些注入全部 **opt-out**（默认开启），且无文档说明。

本方案通过 **monkey-patch** 机制，在 **不修改任何策略代码** 的前提下，自动清除所有注入。

### 核心保证

- **零改动策略代码**：不改 `import`、不改 `ccxt.binance({...})`、不改 `create_order()`
- **透明安全**：所有 broker/partner/builder fee 注入自动清除
- **可审计**：结构化 JSON 证据输出
- **可回滚**：一个开关恢复原始行为
- **最少副作用**：仅替换 ccxt 交易所类构造器，不修改全局状态

---

## 一分钟接入

### 前置条件

```bash
# 确保这三个文件在同一目录（或都在 PYTHONPATH 上）：
#   ccxt_safe.py              — 核心安全模块
#   ccxt_safe_bootstrap.py    — 启动器（monkey-patch）
#   sitecustomize.py          — 自动启用（Mode A 可选）
```

### 模式 A：sitecustomize 自动启用（最零改动）

**原理**：Python 启动时自动 import `sitecustomize.py`，无需改任何代码。

```bash
# 步骤 1：将三个文件放到同一目录
cp ccxt_safe.py ccxt_safe_bootstrap.py sitecustomize.py /opt/ccxt_safe/

# 步骤 2：设置 PYTHONPATH
export PYTHONPATH=/opt/ccxt_safe:$PYTHONPATH

# 步骤 3：直接运行策略 — 无需改一行代码
python my_strategy.py
```

**验证生效**：

```bash
python -c "
import ccxt
ex = ccxt.okx({'apiKey':'x','secret':'y','password':'z'})
print('Bootstrap active:', hasattr(ex, '_ccxt_safe_bootstrap'))
print('brokerId:', repr(ex.options.get('brokerId')))
"
# 输出：
#   Bootstrap active: True
#   brokerId: ''
```

**替代放置方式**（放入 site-packages）：

```bash
# 找到 site-packages 路径
SITE=$(python -c "import site; print(site.getsitepackages()[0])")
cp ccxt_safe.py ccxt_safe_bootstrap.py sitecustomize.py "$SITE/"
# 无需设 PYTHONPATH，直接运行策略
```

> **注意**：如果 site-packages 已有 `sitecustomize.py`，请将内容合并，而非覆盖。

### 模式 B：显式一行启用

**适用场景**：不方便修改 PYTHONPATH，或已有 sitecustomize。

只需在**入口文件最上方**加 1 行：

```python
import ccxt_safe_bootstrap; ccxt_safe_bootstrap.enable()  # 策略代码 0 改动

# ---- 以下为原有策略代码，一行不改 ----
import ccxt
ex = ccxt.binance({'apiKey': '...', 'secret': '...'})
order = ex.create_order('BTC/USDT', 'limit', 'buy', 0.001, 50000)
```

> **允许**改入口启动文件（如 `main.py` / `run.py`），**不改**策略逻辑文件。

---

## 生产配置（环境变量）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CCXT_SAFE_ENABLE` | `1` | 主开关。设 `0` 完全禁用 patch |
| `CCXT_SAFE_STRICT` | `1` | 严格模式。发现可疑字段时 raise |
| `CCXT_SAFE_DRY_RUN` | `1/0` | 干跑模式。阻止所有网络请求（验证用） |
| `CCXT_SAFE_AUDIT` | `raise` | 审计动作：`raise`（阻断）或 `warn`（仅日志） |
| `CCXT_SAFE_OPT_IN` | `0` | 允许用户使用自己的 brokerId（拒绝 CCXT 默认值） |
| `CCXT_SAFE_LOG` | *(stderr)* | 证据日志文件路径 |

### 推荐生产配置

```bash
# .env 或 docker-compose.yml 中
CCXT_SAFE_ENABLE=1
CCXT_SAFE_STRICT=1
CCXT_SAFE_DRY_RUN=0
CCXT_SAFE_AUDIT=raise
CCXT_SAFE_OPT_IN=0
CCXT_SAFE_LOG=/var/log/ccxt_safe_audit.jsonl
```

### 调试/验证配置

```bash
# dry-run 模式 — 阻止真实请求，验证 patch 生效
CCXT_SAFE_ENABLE=1
CCXT_SAFE_DRY_RUN=1
CCXT_SAFE_AUDIT=warn
```

---

## 验证方法

### 1. Dry-run 验证（不需要真实下单）

```bash
# 设置 dry-run 模式
export CCXT_SAFE_DRY_RUN=1
export CCXT_SAFE_AUDIT=warn

python -c "
import ccxt_safe_bootstrap; ccxt_safe_bootstrap.enable()
import ccxt

# 测试 OKX
ex = ccxt.okx({'apiKey':'x','secret':'y','password':'z'})
print('OKX brokerId:', repr(ex.options.get('brokerId')))
try:
    ex.fetch_balance()
except Exception as e:
    print('Intercepted:', type(e).__name__)

# 测试 Binance
ex2 = ccxt.binance({'apiKey':'x','secret':'y'})
print('Binance broker:', repr(ex2.options.get('broker')))

print('All checks passed.')
"
```

### 2. 完整验证脚本

```bash
# 使用交付的验证脚本
python verify_no_injection.py
```

### 3. 观察审计日志

```bash
# 实时查看证据输出
export CCXT_SAFE_LOG=/tmp/ccxt_audit.jsonl
python my_strategy.py &

# 另一个终端
tail -f /tmp/ccxt_audit.jsonl | python -m json.tool
```

证据记录格式：

```json
{
  "exchange": "okx",
  "type": "header",
  "key": "X-CHANNEL-API-CODE",
  "value": "p4sve",
  "url": "https://...",
  "method": "POST",
  "ts": "2025-01-15T08:30:00.123Z"
}
```

### 4. 检查 bootstrap 状态

```python
import ccxt_safe_bootstrap
print(ccxt_safe_bootstrap.status())
# {'enabled': True, 'version': '1.0.0', 'exchanges_patched': 97, 'env': {...}}
```

---

## 常见坑与解决方案

### 坑 1：Binance 合约 hardcoded defaultId

**问题**：Binance `sign()` 中有硬编码的 `defaultId`（如 `x-xcKtGhcu`），即使把 `options.broker` 设为 `{}`，合约路径仍会通过 `safe_string({}, marketType, defaultId)` 注入 broker 前缀到 `newClientOrderId`。

**为什么不用改策略**：Bootstrap 自动对 `create_order()` 安装方法级代理。代理在调用前检查 `params` 是否包含 `newClientOrderId`，若缺失则自动补一个干净的 UUID（无任何 broker 前缀）。CCXT 内部检测到 `clientOrderId` 已存在时会跳过注入。

```python
# 策略代码不变：
order = ex.create_order('BTC/USDT:USDT', 'limit', 'buy', 0.001, 50000)
# Bootstrap 内部等效于：
# params['newClientOrderId'] = 'a1b2c3d4e5f6g7h8i9j0k1'  # clean UUID
# ex._original_create_order(symbol, type, side, amount, price, params)
```

### 坑 2：OKX clOrdId / tag 前缀

**问题**：OKX `create_order()` 在 `brokerId` 非 None 时注入 `clOrdId = brokerId + uuid16()` 和 `tag = brokerId`。`sign()` 层有硬编码 fallback `'6b9ad766b55dBCDE'`。

**为什么不用改策略**：
- Bootstrap 将 `options.brokerId` 设为 `''`（空字符串），使前缀为空
- 方法代理自动注入干净的 `clOrdId` 参数
- Scrubber 在 `sign()` 后删除空值的 `tag` 字段

### 坑 3：HTX / Bittrade client-order-id 前缀

**问题**：HTX 的 `create_order()` 用 `broker.id + uuid()` 生成 `client-order-id`。如果 `broker.id` 被设为 Python `None`，`None + str` 会抛 TypeError。

**解决**：`SAFE_OVERRIDES` 将 `broker` 设为 `{'id': ''}` 而非 `None`。方法代理自动补 `client-order-id = clean_uuid`。

### 坑 4：KuCoin partner headers 带签名验证

**问题**：KuCoin 的 `sign()` 在 `partnerId` 和 `partnerSecret` 都非 None 时注入 `KC-API-PARTNER*` 三个 header（含 HMAC 签名）。

**解决**：`SAFE_OVERRIDES` 将 `partner` 设为 `{}`，使 `partnerId = safe_string({}, 'id')` 返回 None → 跳过整个注入分支。Scrubber 作为纵深防御，删除残留的空 KC-API-PARTNER 头。

### 坑 5：Hyperliquid 链上授权交易

**问题**：Hyperliquid 的 `builderFee` 默认 `True`，会发起链上 `approveBuilderFee` 交易授权 builder 收费，`setReferrer` 设置链上 referral。这些是**真实链上交易**。

**解决**：Bootstrap 强制 `block_onchain=True`：
- `options.builderFee = False`（跳过 approve 流程）
- `options.refSet = True`（假装已设过 ref）
- `initialize_client` / `approve_builder_fee` / `set_ref` 方法被替换为 blocked stub
- `sign()` 层深度拦截：检测 `action.type` 为 `approveBuilderFee` / `setReferrer` 时 raise

---

## 回滚方案

### 方法 1：环境变量禁用（推荐）

```bash
# 完全禁用 — 不做任何 patch
CCXT_SAFE_ENABLE=0 python my_strategy.py
```

### 方法 2：代码禁用

```python
import ccxt_safe_bootstrap
ccxt_safe_bootstrap.enable()

# ... 运行策略 ...

# 需要回滚时：
ccxt_safe_bootstrap.disable()
# 此后新建的 exchange 实例不再有安全保护
# 已创建的实例保持安全状态
```

### 方法 3：获取原始类

```python
# 需要绕过安全层（如调试）：
OrigBinance = ccxt_safe_bootstrap.get_original_class('binance')
raw_ex = OrigBinance({'apiKey': '...', 'secret': '...'})
# raw_ex 没有任何安全保护
```

### 快速定位问题

```python
# 检查实例是否被 bootstrap 保护
print(hasattr(ex, '_ccxt_safe_bootstrap'))  # True = 已保护

# 查看当前状态
import ccxt_safe_bootstrap
print(ccxt_safe_bootstrap.status())

# 查看某个交易所是否有安全覆盖
from ccxt_safe import SAFE_OVERRIDES
print(SAFE_OVERRIDES.get('binance'))
```

---

## 升级 ccxt 的流程

### 标准流程

```bash
# 1. 升级 ccxt
pip install --upgrade ccxt

# 2. 扫描新增注入点
python scan_ccxt_injection.py
# 若输出 PASS → 无新增注入，安全
# 若输出 FAIL → 有新增交易所的注入，需要处理

# 3. 若有新增：在 ccxt_safe.py 的 SAFE_OVERRIDES 中补充覆盖
# 参考现有条目的格式和审计依据

# 4. 确认覆盖完成后，刷新 baseline
python scan_ccxt_injection.py --refresh-baseline

# 5. 运行测试
python -m pytest tests/test_ccxt_safe.py -v

# 6. 运行验证脚本
python verify_no_injection.py
```

### CI 集成

```yaml
# .github/workflows/ccxt-safety.yml
name: CCXT Safety Check
on:
  schedule:
    - cron: '0 8 * * 1'  # 每周一
  push:
    paths:
      - 'requirements*.txt'
      - 'ccxt_safe*.py'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install ccxt
      - run: python scan_ccxt_injection.py
      - run: python verify_no_injection.py
      - run: python -m pytest tests/test_ccxt_safe.py -v
```

### baseline 说明

`broker-scan-baseline.json` 使用 `filename|keyword|sha1(snippet)` 格式的 key，不依赖行号。ccxt 升级导致行号变化时不会误报，只有真正新增的注入点才会触发 FAIL。

---

## 架构说明

```
策略代码                    ccxt_safe_bootstrap                  ccxt_safe
─────────                  ──────────────────                  ─────────
import ccxt        ──→    (monkey-patched ccxt)
ccxt.binance({})   ──→    _SafeWrapper.__init__()
                            ├─ super().__init__()  (原始构造)
                            ├─ _apply_safety()
                            │   ├─ SAFE_OVERRIDES 覆盖       ←── ccxt_safe.SAFE_OVERRIDES
                            │   ├─ _patch_hyperliquid()       ←── ccxt_safe._patch_hyperliquid
                            │   ├─ _verify_overrides()        ←── ccxt_safe._verify_overrides
                            │   ├─ _install_audit()           ←── ccxt_safe._scrub_sign_result
                            │   │   ├─ scrub sign() output         _scan_for_suspects
                            │   │   └─ emit evidence JSON
                            │   └─ _wrap_order_methods()
                            │       ├─ create_order → 自动补 clean OID
                            │       ├─ create_orders → 批量补 clean OID
                            │       └─ edit_order → 同上
                            └─ stamp _ccxt_safe_bootstrap=True

ex.create_order()  ──→    _safe_create_order()
                            ├─ inject clean clientOrderId
                            └─ original create_order()
                                └─ sign() → audited_sign()
                                    ├─ scrub headers/body
                                    ├─ scan for suspects
                                    └─ emit evidence
```

### isinstance 兼容性

```python
import ccxt
ex = ccxt.binance({'apiKey': 'x', 'secret': 'y'})

isinstance(ex, ccxt.Exchange)   # True ✓
isinstance(ex, ccxt.binance)    # True ✓ (包装后的类是原始类的子类)
type(ex).__name__               # 'binance' ✓
```

---

## 文件清单

| 文件 | 用途 |
|------|------|
| `ccxt_safe.py` | 核心模块：SafetyPolicy、SAFE_OVERRIDES、scrubber、审计钩子 |
| `ccxt_safe_bootstrap.py` | 启动器：monkey-patch + 方法代理 + 环境变量配置 |
| `sitecustomize.py` | Mode A 自动启用 |
| `verify_no_injection.py` | 最小验证脚本（smoke test） |
| `scan_ccxt_injection.py` | CI 扫描脚本 |
| `broker-scan-baseline.json` | 扫描基线 |
| `tests/test_ccxt_safe.py` | 核心模块测试 |
| `USAGE.md` | 核心模块使用指南 |
| `ZERO_CHANGE_GUIDE.md` | 本文档 — 零改动接入指南 |
