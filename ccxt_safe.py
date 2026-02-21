"""
ccxt_safe.py — CCXT 安全封装模块
防止隐藏抽佣 / 返佣归因劫持 / builder fee 授权

基于对 python/ccxt/*.py 源码的逐项审计构建。
"""
import uuid
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, Literal

import ccxt

logger = logging.getLogger('ccxt_safe')


# ============================================================================
# SafetyPolicy — 策略化配置
# ============================================================================

@dataclass
class SafetyPolicy:
    """控制安全封装的行为策略。"""
    strict: bool = True
    allow_user_overrides: bool = False
    allow_broker_opt_in: bool = False
    scrub_empty_fields: bool = True
    block_onchain: bool = True
    audit_on_findings: Literal['warn', 'raise'] = 'raise'

    def __post_init__(self):
        if not self.strict and self.audit_on_findings == 'raise':
            self.audit_on_findings = 'warn'


# 受保护的 options keys — 触及这些 key 需要显式 opt-in
PROTECTED_KEYS = {
    'brokerId', 'broker', 'partner', 'builderFee', 'refSet',
    'approvedBuilderFee', 'builder', 'ref', 'feeRate', 'feeInt',
    'id', 'keyBrokerId',
}

# ============================================================================
# 【交付物 2】SAFE_OVERRIDES — 每个交易所的禁用配置
#
# 格式: exchange_id -> {options_key: disable_value}
#
# 每条都附带审计依据（Python 源码中的判断方式）
# ============================================================================

SAFE_OVERRIDES: Dict[str, Dict[str, Any]] = {
    # ── CRITICAL ──────────────────────────────────────────────────────────
    'hyperliquid': {
        # handle_builder_fee_approval(): safe_bool(options, 'builderFee', True)
        #   → if not buildFee: return False
        #   设 False 跳过整个 approve 流程
        'builderFee': False,
        # set_ref(): safe_bool(options, 'refSet', False)
        #   → if refSet: return True (跳过)
        #   设 True 让它以为已经设过了
        'refSet': True,
        # create_orders_request(): safe_bool(options, 'approvedBuilderFee', False)
        #   → if approved: 注入 builder 字段
        #   设 False 阻止每单注入
        'approvedBuilderFee': False,
        # 清空 builder 地址和 ref code 作为纵深防御
        'builder': '',
        'ref': '',
        'feeRate': '',
        'feeInt': 0,
    },

    'kucoin': {
        # sign(): safe_dict(options, 'partner', {})
        #   → partner = safe_value(partner, 'spot'/'future', partner)
        #   → partnerId = safe_string(partner, 'id')
        #   → if (partnerId is not None) and (partnerSecret is not None): 注入
        #   设 {} 使 partnerId 为 None → 跳过
        'partner': {},
    },

    # ── HIGH ──────────────────────────────────────────────────────────────
    'okx': {
        # create_order(): safe_string(options, 'brokerId')
        #   → if brokerId is not None: 注入 tag + clOrdId
        # sign(): safe_string(options, 'brokerId', '6b9ad766b55dBCDE')
        #   → 有硬编码 fallback！设 None 无法阻止 sign() 层
        #   → 必须设 '' 空字符串：safe_string 返回 ''，
        #     sign() 中 clOrdId = '' + uuid（前缀为空），tag = ''（空标签）
        'brokerId': '',
    },

    'binance': {
        # create_order() spot: safe_dict(options, 'broker')
        #   → if broker is not None: ... safe_string(broker, 'spot')
        # create_order() contract + sign(): safe_dict(options, 'broker', {})
        #   → safe_string(broker, marketType, defaultId) 有硬编码 fallback
        #   → 设 None: safe_dict 对已存在的 None 值返回 None，
        #     后续 safe_string(None, ...) 返回 None → 但 contract 路径
        #     用 safe_dict(..., {}) 当 key 存在且为 None 时返回 None
        #     → safe_string(None, ..., defaultId) 返回 defaultId → 仍注入！
        #   → 必须设 {} 空字典：safe_string({}, 'spot') 返回 None → 跳过 spot
        #     但 contract: safe_string({}, marketType, defaultId) → 返回 defaultId
        #   → 结论：仅靠 options 无法完全阻止 contract 路径，需配合传 clientOrderId
        #   → 我们设 {} 并在 safe_create_order 中自动生成无前缀 clientOrderId
        'broker': {},
    },

    # binance 子交易所 — 继承同一套 broker 注入逻辑，必须同样覆盖
    'binanceusdm': {
        # USDⓈ-M 合约：sign() 中 safe_string(broker, 'future', defaultId)
        #   → defaultId = 'x-cvBPrNm9'（hardcoded）
        #   → 必须设 {} + 配合 clean clientOrderId
        'broker': {},
    },
    'binancecoinm': {
        # COIN-M 合约：同 binanceusdm 逻辑
        'broker': {},
    },
    'binanceus': {
        # Binance US：同 binance spot 逻辑
        'broker': {},
    },

    'bybit': {
        # sign(): safe_string(options, 'brokerId')
        #   → if brokerId is not None: headers['Referer'] = brokerId
        #   设 None: safe_string 返回 None → 跳过
        #   注意：'' 空字符串会通过 is not None 检查！必须用 None
        'brokerId': None,
    },

    'derive': {
        # create_order(): safe_string(options, 'id', '0x0ad42b8e...')
        #   → 无条件注入 referral_code，有硬编码 fallback
        #   → 设 '' 空字符串：referral_code 为空串（仍发送但无归因）
        #   注意：options['id'] 与 self.id 不同，safe_string 读 options dict
        'id': '',
    },

    'bitget': {
        # sign(): safe_string(options, 'broker')
        #   → 无条件写入 X-CHANNEL-API-CODE header
        #   → 有 describe() 默认 'p4sve'，safe_string 无 fallback 但 options 有值
        #   → 设 '': header 值为空串
        'broker': '',
    },

    'bingx': {
        # sign(): safe_string(options, 'broker', 'CCXT')
        #   → 无条件写入 X-SOURCE-KEY header，有硬编码 fallback
        #   → 设 '': safe_string 返回 '' 而非 fallback
        'broker': '',
    },

    'bitmart': {
        # sign(): safe_string(options, 'brokerId', 'CCXTxBitmart000')
        #   → 无条件写入 X-BM-BROKER-ID header，有硬编码 fallback
        #   → 设 '': safe_string 返回 ''
        'brokerId': '',
    },

    'bitmex': {
        # create_order(): safe_string(options, 'brokerId', 'CCXT')
        #   → 无条件写入 text 字段，有硬编码 fallback
        # edit_order(): 同上
        #   → 设 '': text 字段为空串
        'brokerId': '',
    },

    'hashkey': {
        # sign(): safe_string(options, 'broker', '10000700011')
        #   → 无条件写入 INPUT-SOURCE header + broker_sign header
        #   → 有硬编码 fallback
        #   → 设 '': INPUT-SOURCE 为空串
        'broker': '',
    },

    'mexc': {
        # sign(): safe_string(options, 'broker', 'CCXT')
        #   → 无条件写入 source header（两个分支），有硬编码 fallback
        #   → 设 '': source 为空串
        'broker': '',
    },

    'cryptocom': {
        # create_order(): safe_string(options, 'broker', 'CCXT')
        #   → 无条件写入 broker_id body 字段（两处），有硬编码 fallback
        #   → 设 '': broker_id 为空串
        'broker': '',
    },

    'coinex': {
        # create_order_request(): safe_string(options, 'brokerId', defaultId)
        #   → if clientOrderId is None: 注入 client_id = brokerId + '-' + uuid
        # sign(): safe_value(options, 'brokerId', defaultId)
        #   → if clientOrderId is None: 注入 client_id = brokerId + '_' + uuid
        #   → 两处都有硬编码 fallback 'x-167673045'
        #   → 设 '': client_id 前缀为空
        'brokerId': '',
    },

    'htx': {
        # create_order(): safe_value(options, 'broker', {})
        #   → brokerId = safe_string(broker, 'id')
        #   → if clientOrderId is None: client-order-id = brokerId + uuid()
        #   → 条件：clientOrderId is None（有条件）
        # create_contract_order_request(): 同上但 channel_code 无条件
        #   → 设 {}: safe_string({}, 'id') 返回 None
        #   → spot: brokerId 为 None，None + uuid() 会出错 → 实际上
        #     Python 中 None + str 会 TypeError → 需要设 {'id': ''}
        #   → 更安全：设 {'id': ''} 使前缀为空
        'broker': {'id': ''},
    },

    'bittrade': {
        # create_order(): safe_value(options, 'broker', {})
        #   → brokerId = safe_string(broker, 'id')
        #   → client-order-id = brokerId + uuid()
        #   → 同 htx 逻辑
        'broker': {'id': ''},
    },

    'blofin': {
        # create_order_request(): safe_string(options, 'brokerId', 'ec6dd3a7dd982d0b')
        #   → 无条件写入 brokerId body 字段，有硬编码 fallback
        # create_tpsl_order_request(): 同上
        #   → 设 '': brokerId 为空串
        'brokerId': '',
    },

    'phemex': {
        # create_order(): safe_string(options, 'brokerId', 'CCXT123456')
        #   → if brokerId is not None: clOrdID = brokerId + uuid16()
        #   → 有硬编码 fallback，设 None 无效
        #   → 设 '': clOrdID = '' + uuid（前缀为空）
        'brokerId': '',
    },

    'coinbase': {
        # create_order(): safe_string(options, 'brokerId', 'ccxt')
        #   → 用作 clientOrderId 前缀，有硬编码 fallback
        #   → 设 '': 前缀为空
        'brokerId': '',
    },

    'coinbaseinternational': {
        # create_order(): safe_string(options, 'brokerId', 'nfqkvdjp')
        #   → 用作 clientOrderId 前缀，有硬编码 fallback
        #   → 设 '': 前缀为空
        'brokerId': '',
    },

    'coincatch': {
        # sign(): safe_string(options, 'brokerId', '47cfy')
        #   → 无条件写入 X-CHANNEL-API-CODE header，有硬编码 fallback
        #   → 设 '': header 为空串
        'brokerId': '',
    },

    'whitebit': {
        # create_order(): safe_string(options, 'brokerId')
        #   → if brokerId is not None: clientOrderId = brokerId + uuid16()
        #   → 无硬编码 fallback，但 describe() 默认 'ccxt'
        #   → 设 None: safe_string 返回 None → 跳过
        'brokerId': None,
    },

    'woo': {
        # sign(): safe_string(options, 'brokerId', applicationId)
        #   → 无条件写入 broker_id/brokerId body 字段
        #   → applicationId 是硬编码 fallback 'bc830de7-...'
        #   → 设 '': 前缀为空
        'brokerId': '',
    },

    'woofipro': {
        # sign(): safe_string(options, 'brokerId', 'CCXT')
        #   → 无条件写入 order_tag，有硬编码 fallback
        # EIP-712: safe_string(options, 'keyBrokerId', 'woofi_pro')
        #   → 写入签名 payload
        'brokerId': '',
        'keyBrokerId': '',
    },

    'modetrade': {
        # sign(): safe_string(options, 'brokerId', 'CCXTMODE')
        #   → 无条件写入 order_tag，有硬编码 fallback
        # EIP-712: safe_string(options, 'keyBrokerId', 'mode')
        'brokerId': '',
        'keyBrokerId': '',
    },

    'apex': {
        # create_order(): safe_string(options, 'brokerId', '6956')
        #   → 无条件写入 brokerId body 字段，有硬编码 fallback
        'brokerId': '',
    },

    'tokocrypto': {
        # create_order(): safe_value(options, 'broker')
        #   → if broker is not None: brokerId = safe_string(broker, 'marketType')
        #   → if brokerId is not None: clientId = brokerId + uuid22()
        #   → 设 None: 外层 if 跳过
        'broker': None,
    },

    'paradex': {
        # sign(): safe_string(options, 'broker', 'CCXT')
        #   → 无条件写入 PARADEX-PARTNER header，有硬编码 fallback
        'broker': '',
    },

    'kucoinfutures': {
        # 继承 kucoin 的 partner 机制
        'partner': {},
    },
}

# 高风险交易所列表（必须经过安全处理）
HIGH_RISK_EXCHANGES = set(SAFE_OVERRIDES.keys())

# 审计扫描的可疑字段关键词
SUSPECT_HEADER_KEYS = [
    'KC-API-PARTNER', 'KC-API-PARTNER-SIGN', 'KC-API-PARTNER-VERIFY',
    'KC-BROKER-NAME', 'X-BM-BROKER-ID', 'X-CHANNEL-API-CODE',
    'X-SOURCE-KEY', 'INPUT-SOURCE', 'broker_sign', 'Referer',
    'PARADEX-PARTNER',
]
SUSPECT_BODY_KEYS = [
    'brokerId', 'broker_id', 'broker', 'partner', 'tag',
    'newClientOrderId', 'clientOrderId', 'clOrdId', 'clOrdID',
    'client_id', 'client-order-id', 'order_tag', 'text',
    'referral_code', 'builder', 'channel_code', 'source',
    'clientId',
]
# Known CCXT default broker values — if any of these appear, injection is active
KNOWN_BROKER_VALUES = {
    '6b9ad766b55dBCDE', 'x-TKT5PX2F', 'x-cvBPrNm9', 'x-xcKtGhcu',
    'CCXT', 'ccxt', 'CCXT1', 'CCXTxBitmart000', 'p4sve', '47cfy',
    'x-167673045', 'AA03022abc', 'ec6dd3a7dd982d0b', 'CCXT123456',
    'nfqkvdjp', 'ccxtfutures', 'bc830de7-50f3-460b-9ee0-f430f83f9dad',
    'CCXTMODE', '6956', '10000700011',
    '0x6530512A6c89C7cfCEbC3BA7fcD9aDa5f30827a6',
    '0x0ad42b8e602c2d3d475ae52d678cf63d84ab2749',
    '9e58cc35-5b5e-4133-92ec-166e3f077cb8',
    '1b327198-f30c-4f14-a0ac-918871282f15',
}


# ============================================================================
# 异常类
# ============================================================================

class SafeBlockedError(RuntimeError):
    """安全模块阻止了一个危险操作"""
    pass


class AuditInterceptError(RuntimeError):
    """审计拦截模式：请求已构造但被阻止发送"""
    def __init__(self, method, url, headers, body):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        super().__init__(f"AUDIT_INTERCEPT: {method} {url}")


# ============================================================================
# Hyperliquid 专项补丁
# ============================================================================

def _patch_hyperliquid(exchange, policy: Optional[SafetyPolicy] = None):
    """防御性补丁：即使 options 被误改也不会执行链上授权"""
    if policy and not policy.block_onchain:
        return
    def _blocked_initialize_client(self_=None):
        logger.warning("[ccxt_safe] Hyperliquid initializeClient blocked")
        return True

    def _blocked_approve_builder_fee(self_=None, *a, **kw):
        raise SafeBlockedError("SAFE_BLOCKED_ONCHAIN_TX: approveBuilderFee")

    def _blocked_set_ref(self_=None):
        raise SafeBlockedError("SAFE_BLOCKED_ONCHAIN_TX: setReferrer")

    exchange.initialize_client = _blocked_initialize_client
    exchange.approve_builder_fee = _blocked_approve_builder_fee
    exchange.set_ref = _blocked_set_ref
    # 同时 patch camelCase 别名（ccxt 内部可能用任一形式）
    if hasattr(exchange, 'initializeClient'):
        exchange.initializeClient = _blocked_initialize_client
    if hasattr(exchange, 'approveBuilderFee'):
        exchange.approveBuilderFee = _blocked_approve_builder_fee
    if hasattr(exchange, 'setRef'):
        exchange.setRef = _blocked_set_ref
    if hasattr(exchange, 'handle_builder_fee_approval'):
        exchange.handle_builder_fee_approval = _blocked_initialize_client
    if hasattr(exchange, 'handleBuilderFeeApproval'):
        exchange.handleBuilderFeeApproval = _blocked_initialize_client

    # 深层拦截：hook sign() 阻止任何包含危险 action.type 的请求体
    _BLOCKED_ACTIONS = {'approveBuilderFee', 'setReferrer'}
    original_sign = exchange.sign

    def _guarded_sign(path, api='public', method='GET',
                      params=None, headers=None, body=None):
        # 检查 body（可能是 dict 或 JSON string）
        payload = body
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                payload = None
        if isinstance(payload, dict):
            action = payload.get('action', {})
            if isinstance(action, dict):
                atype = action.get('type', '')
                if atype in _BLOCKED_ACTIONS:
                    raise SafeBlockedError(
                        f"SAFE_BLOCKED_ONCHAIN_TX: action.type={atype}")
        return original_sign(path, api, method, params, headers, body)

    exchange.sign = _guarded_sign


# ============================================================================
# KuCoin 专项验证
# ============================================================================

def _verify_kucoin_clean(exchange) -> Optional[str]:
    """验证 kucoin sign() 不再产生 KC-API-PARTNER* 头"""
    partner = exchange.safe_dict(exchange.options, 'partner', {})
    for sub in ('spot', 'future'):
        p = exchange.safe_value(partner, sub, partner)
        pid = exchange.safe_string(p, 'id')
        pkey = exchange.safe_string_2(p, 'secret', 'key')
        if pid is not None and pkey is not None:
            return f"partner.{sub}.id={pid} still present"
    return None


# ============================================================================
# Fail-closed 验证
# ============================================================================

def _verify_overrides(exchange, exchange_id: str,
                      policy: Optional[SafetyPolicy] = None):
    """验证禁用后 options 中不再包含已知 broker 默认值。
    strict 模式：检查无 CCXT 默认归因值残留（不再死等于 SAFE_OVERRIDES）。
    opt-in 模式：仅检查残留的 KNOWN_BROKER_VALUES。
    """
    overrides = SAFE_OVERRIDES.get(exchange_id, {})
    is_opt_in = policy and policy.allow_broker_opt_in

    for key, expected in overrides.items():
        actual = exchange.options.get(key)
        if actual != expected:
            # opt-in 模式下，用户覆盖的受保护 key 跳过精确匹配检查
            if is_opt_in and key in PROTECTED_KEYS:
                # 但仍拒绝 CCXT 默认值
                if isinstance(actual, str) and actual in KNOWN_BROKER_VALUES:
                    raise SafeBlockedError(
                        f"[{exchange_id}] options['{key}'] = {actual!r} "
                        f"is a known CCXT default broker value"
                    )
                continue
            raise SafeBlockedError(
                f"[{exchange_id}] options['{key}'] = {actual!r}, "
                f"expected {expected!r} after override"
            )
    # 扫描 options 中是否残留已知 broker 值
    for key, val in exchange.options.items():
        if isinstance(val, str) and val in KNOWN_BROKER_VALUES:
            if key not in overrides:
                raise SafeBlockedError(
                    f"[{exchange_id}] options['{key}'] = {val!r} "
                    f"matches known CCXT broker value"
                )
    # KuCoin 专项
    if exchange_id in ('kucoin', 'kucoinfutures'):
        err = _verify_kucoin_clean(exchange)
        if err:
            raise SafeBlockedError(f"[{exchange_id}] {err}")


# ============================================================================
# 【交付物 1】核心 API
# ============================================================================

def create_safe_exchange(exchange_id: str, *,
                         policy: Optional[SafetyPolicy] = None,
                         **user_config) -> ccxt.Exchange:
    """
    创建已清理 broker/partner/builder 注入的 ccxt 交易所实例。

    policy 控制安全行为（默认 strict）。
    用户 options 中触及受保护 key 时：
      - 默认拒绝（除非 policy.allow_broker_opt_in=True）
      - opt-in 时仍拒绝 KNOWN_BROKER_VALUES（防止误用 CCXT 默认值）
    """
    if policy is None:
        policy = SafetyPolicy()

    ExchangeClass = getattr(ccxt, exchange_id, None)
    if ExchangeClass is None:
        raise ValueError(f"Unknown exchange: {exchange_id}")

    user_opts = user_config.pop('options', {}) or {}
    exchange = ExchangeClass(user_config)

    # 构建最终 options：安全覆盖为基础
    safe_opts = dict(SAFE_OVERRIDES.get(exchange_id, {}))

    # 处理用户 options
    for k, v in user_opts.items():
        if k in PROTECTED_KEYS and k in safe_opts and v != safe_opts[k]:
            if not policy.allow_broker_opt_in:
                raise SafeBlockedError(
                    f"[{exchange_id}] options['{k}']={v!r} touches protected key. "
                    f"Set policy.allow_broker_opt_in=True to override."
                )
            if isinstance(v, str) and v in KNOWN_BROKER_VALUES:
                raise SafeBlockedError(
                    f"[{exchange_id}] options['{k}']={v!r} is a known CCXT "
                    f"default broker value — cannot opt-in with CCXT's own ID."
                )
            logger.warning(
                f"[ccxt_safe] OPT-IN: {exchange_id} options['{k}']={v!r}"
            )
            safe_opts[k] = v
        else:
            safe_opts[k] = v

    # 直接赋值，绕过 deep_extend
    for k, v in safe_opts.items():
        exchange.options[k] = v

    # 存储 policy 供后续 scrubber/audit 使用
    exchange._ccxt_safe_policy = policy

    # Hyperliquid 专项补丁
    if exchange_id == 'hyperliquid':
        _patch_hyperliquid(exchange, policy)

    # Fail-closed 验证
    if exchange_id in HIGH_RISK_EXCHANGES:
        _verify_overrides(exchange, exchange_id, policy)

    return exchange


# ============================================================================
# 【交付物 1.5】Runtime 审计钩子
# ============================================================================

def _scan_for_suspects(headers: dict, body, exchange_id: str) -> List[Dict]:
    """扫描 headers/body 中的可疑 broker 字段，返回发现列表。

    对 clientOrderId 类字段（_OID_BODY_KEYS）仅在 **值** 包含已知 broker
    前缀时才报告；对纯归因字段（其余 SUSPECT_BODY_KEYS）只要 key 出现
    即为可疑。
    """
    findings = []
    if headers:
        for k, v in headers.items():
            for sk in SUSPECT_HEADER_KEYS:
                if k.lower() == sk.lower() and v:
                    findings.append({
                        'type': 'header', 'key': k,
                        'value': v, 'exchange': exchange_id,
                    })
    if body:
        body_str = body if isinstance(body, str) else json.dumps(body)
        # 解析 body 中的 key=value 对（支持 URL-encoded 和 JSON）
        body_values = _extract_body_values(body_str)
        for sk in SUSPECT_BODY_KEYS:
            if sk not in body_str:
                continue
            # OID 类字段：只在值包含已知 broker 前缀时报告
            if sk in _OID_BODY_KEYS:
                val = body_values.get(sk, '')
                if not _value_has_broker_prefix(val):
                    continue  # clean OID — 不报告
            findings.append({
                'type': 'body', 'key': sk,
                'snippet': body_str[:300], 'exchange': exchange_id,
            })
            break  # one finding per body is enough
    return findings


def _extract_body_values(body_str: str) -> Dict[str, str]:
    """从 URL-encoded 或 JSON body 中提取 key→value 映射。"""
    # 尝试 JSON
    try:
        obj = json.loads(body_str)
        if isinstance(obj, dict):
            return {k: str(v) for k, v in obj.items()}
    except (json.JSONDecodeError, TypeError):
        pass
    # URL-encoded: key=value&key2=value2
    result = {}
    for pair in body_str.split('&'):
        if '=' in pair:
            k, _, v = pair.partition('=')
            result[k] = v
    return result


def _value_has_broker_prefix(val: str) -> bool:
    """检查值是否以已知 CCXT broker 标识开头。"""
    if not val:
        return False
    for bv in KNOWN_BROKER_VALUES:
        if val.startswith(bv):
            return True
    return False


# Header keys to always delete (case-insensitive match)
_SCRUB_HEADER_SET = {k.lower() for k in SUSPECT_HEADER_KEYS}

# Body keys that are pure attribution (safe to remove)
_SCRUB_BODY_KEYS = {
    'tag', 'brokerId', 'broker_id', 'referral_code', 'order_tag',
    'builder', 'channel_code', 'source', 'broker_sign', 'text',
}
# Body keys that carry user data — only scrub the broker PREFIX, never delete
_OID_BODY_KEYS = {
    'newClientOrderId', 'clientOrderId', 'clOrdId', 'clOrdID',
    'client_id', 'client-order-id', 'clientId',
}


def _scrub_sign_result(result: dict, exchange_id: str,
                       policy: SafetyPolicy) -> dict:
    """Post-process sign() output: strip suspect headers and body fields."""
    if not policy.scrub_empty_fields:
        return result

    # --- scrub headers ---
    headers = result.get('headers')
    if headers and isinstance(headers, dict):
        to_del = [k for k in headers
                  if k.lower() in _SCRUB_HEADER_SET
                  and (_is_empty_or_known(headers[k]))]
        for k in to_del:
            del headers[k]

    # --- scrub body ---
    body = result.get('body')
    if body and isinstance(body, str):
        try:
            body_dict = json.loads(body)
            if isinstance(body_dict, dict):
                _scrub_body_dict(body_dict)
                result['body'] = json.dumps(body_dict, separators=(',', ':'))
        except (json.JSONDecodeError, TypeError):
            pass  # url-encoded or non-JSON — leave as-is

    return result


def _is_empty_or_known(val) -> bool:
    """Value is empty, None, or a known CCXT default broker value."""
    if val is None or val == '':
        return True
    return isinstance(val, str) and val in KNOWN_BROKER_VALUES


def _scrub_body_dict(d: dict):
    """In-place remove pure-attribution keys with empty/known values."""
    for k in list(d.keys()):
        if k in _SCRUB_BODY_KEYS and _is_empty_or_known(d.get(k)):
            del d[k]


def enable_audit(exchange, dry_run: bool = False, scrub: bool = True):
    """
    Hook exchange.sign() 和 exchange.fetch() 以捕获、清洗并审计请求。

    scrub=True: 对 sign() 返回结果执行 header/body 清洗（默认开启）。
    dry_run=True: 阻止真实网络请求，抛出 AuditInterceptError（含请求证据）。
    dry_run=False: 允许请求但对可疑字段打印警告或 raise。
    """
    eid = getattr(exchange, 'id', 'unknown')
    policy = getattr(exchange, '_ccxt_safe_policy', SafetyPolicy())
    original_sign = exchange.sign

    def audited_sign(path, api='public', method='GET',
                     params=None, headers=None, body=None):
        result = original_sign(path, api, method, params, headers, body)
        # scrub first, then audit
        if scrub:
            _scrub_sign_result(result, eid, policy)
        r_headers = result.get('headers') or {}
        r_body = result.get('body') or ''
        findings = _scan_for_suspects(r_headers, r_body, eid)
        for f in findings:
            evidence = json.dumps(f, ensure_ascii=False)
            if policy.audit_on_findings == 'raise':
                raise SafeBlockedError(
                    f"[AUDIT][{eid}] suspect field: {evidence}")
            logger.warning(f"[AUDIT][{eid}] {evidence}")
        return result

    exchange.sign = audited_sign

    if dry_run:
        def blocked_fetch(url, method='GET', headers=None, body=None):
            raise AuditInterceptError(method, url, headers, body)
        exchange.fetch = blocked_fetch

    return exchange


# ============================================================================
# 安全下单包装器
# ============================================================================

_CLIENT_OID_KEY = {
    'okx': 'clOrdId', 'binance': 'newClientOrderId',
    'binanceusdm': 'newClientOrderId',
    'binancecoinm': 'newClientOrderId',
    'binanceus': 'newClientOrderId',
    'phemex': 'clOrdID', 'coinex': 'client_id',
    'htx': 'client-order-id', 'bittrade': 'client-order-id',
    'whitebit': 'clientOrderId', 'coinbase': 'clientOrderId',
    'coinbaseinternational': 'clientOrderId',
    'tokocrypto': 'clientId', 'bybit': 'clientOrderId',
}


def _gen_clean_oid() -> str:
    return uuid.uuid4().hex[:22]


def safe_create_order(exchange, symbol, type_, side, amount,
                      price=None, params=None):
    """下单包装器：自动生成无 broker 前缀的 clientOrderId"""
    params = dict(params or {})
    eid = getattr(exchange, 'id', '')
    oid_key = _CLIENT_OID_KEY.get(eid)
    if oid_key and oid_key not in params:
        params[oid_key] = _gen_clean_oid()
    return exchange.create_order(symbol, type_, side, amount, price, params)


def safe_create_orders(exchange, orders: List[Dict]):
    """批量下单包装器"""
    eid = getattr(exchange, 'id', '')
    oid_key = _CLIENT_OID_KEY.get(eid)
    if oid_key:
        for o in orders:
            p = o.get('params', {})
            if oid_key not in p:
                p[oid_key] = _gen_clean_oid()
                o['params'] = p
    return exchange.create_orders(orders)
