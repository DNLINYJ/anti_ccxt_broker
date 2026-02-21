"""
tests/test_ccxt_safe.py — 安全封装模块测试
无需真实网络 / 无需真实下单
"""
import sys
import os
import pytest

# 确保能 import ccxt_safe
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccxt_safe import (
    create_safe_exchange, enable_audit, safe_create_order,
    SafeBlockedError, AuditInterceptError, SafetyPolicy,
    SAFE_OVERRIDES, KNOWN_BROKER_VALUES, HIGH_RISK_EXCHANGES,
    PROTECTED_KEYS, _scrub_sign_result, _is_empty_or_known,
)


# ============================================================================
# 辅助：拦截 sign() 输出并收集 headers/body
# ============================================================================

class SignCapture:
    """捕获 sign() 产出的 headers 和 body"""
    def __init__(self, exchange):
        self.exchange = exchange
        self.captured = []
        self._orig_sign = exchange.sign

    def install(self):
        orig = self._orig_sign
        captured = self.captured

        def capturing_sign(path, api='public', method='GET',
                           params=None, headers=None, body=None):
            result = orig(path, api, method, params, headers, body)
            captured.append({
                'path': path, 'api': api, 'method': method,
                'headers': dict(result.get('headers') or {}),
                'body': result.get('body', ''),
                'url': result.get('url', ''),
            })
            return result

        self.exchange.sign = capturing_sign
        return self

    @property
    def last(self):
        return self.captured[-1] if self.captured else None


# ============================================================================
# 基础测试：create_safe_exchange 对所有 28 个交易所都能创建实例
# ============================================================================

class TestCreateSafeExchange:
    @pytest.mark.parametrize("eid", list(SAFE_OVERRIDES.keys()))
    def test_creates_instance(self, eid):
        ex = create_safe_exchange(eid)
        assert ex is not None
        for key, expected in SAFE_OVERRIDES[eid].items():
            assert ex.options.get(key) == expected, \
                f"{eid}: options['{key}']={ex.options.get(key)!r}, expected {expected!r}"


# ============================================================================
# Hyperliquid: 链上交易必须被阻止
# ============================================================================

class TestHyperliquid:
    def test_builder_fee_blocked(self):
        ex = create_safe_exchange('hyperliquid',
                                  walletAddress='0x' + '0' * 40,
                                  privateKey='0x' + 'a' * 64)
        assert ex.options['builderFee'] is False
        assert ex.options['refSet'] is True
        assert ex.options['approvedBuilderFee'] is False

    def test_initialize_client_noop(self):
        ex = create_safe_exchange('hyperliquid',
                                  walletAddress='0x' + '0' * 40,
                                  privateKey='0x' + 'a' * 64)
        # Should return True without doing anything
        result = ex.initialize_client()
        assert result is True

    def test_approve_builder_fee_raises(self):
        ex = create_safe_exchange('hyperliquid',
                                  walletAddress='0x' + '0' * 40,
                                  privateKey='0x' + 'a' * 64)
        with pytest.raises(SafeBlockedError, match="SAFE_BLOCKED_ONCHAIN_TX"):
            ex.approve_builder_fee('0xabc', '0.01%')

    def test_set_ref_raises(self):
        ex = create_safe_exchange('hyperliquid',
                                  walletAddress='0x' + '0' * 40,
                                  privateKey='0x' + 'a' * 64)
        with pytest.raises(SafeBlockedError, match="SAFE_BLOCKED_ONCHAIN_TX"):
            ex.set_ref()


# ============================================================================
# KuCoin: partner headers 必须消失
# ============================================================================

class TestKuCoin:
    def test_partner_cleared(self):
        ex = create_safe_exchange('kucoin',
                                  apiKey='test', secret='test', password='test')
        assert ex.options.get('partner') == {}

    def test_sign_no_partner_headers(self):
        ex = create_safe_exchange('kucoin',
                                  apiKey='test', secret='test', password='test')
        cap = SignCapture(ex).install()
        # 触发一个 private GET 签名
        ex.sign('accounts', 'private', 'GET', {})
        h = cap.last['headers']
        assert 'KC-API-PARTNER' not in h
        assert 'KC-API-PARTNER-SIGN' not in h
        assert 'KC-API-PARTNER-VERIFY' not in h


# ============================================================================
# OKX: sign() 中 tag/clOrdId 前缀必须为空
# ============================================================================

class TestOKX:
    def test_brokerId_empty(self):
        ex = create_safe_exchange('okx',
                                  apiKey='t', secret='t', password='t')
        assert ex.options.get('brokerId') == ''

    def test_sign_tag_empty(self):
        ex = create_safe_exchange('okx',
                                  apiKey='t', secret='t', password='t')
        cap = SignCapture(ex).install()
        ex.sign('trade/order', 'private', 'POST', {})
        body = cap.last['body']
        # tag 应为空字符串，不应包含已知 broker 值
        for val in KNOWN_BROKER_VALUES:
            assert val not in str(body), f"Found broker value {val} in body"


# ============================================================================
# Binance: broker dict 清空
# ============================================================================

class TestBinance:
    def test_broker_empty_dict(self):
        ex = create_safe_exchange('binance', apiKey='t', secret='t')
        assert ex.options.get('broker') == {}

    def test_sign_no_known_broker_when_oid_provided(self):
        """Binance sign() has hardcoded defaultId fallback for newClientOrderId.
        safe_create_order() handles this by injecting a clean OID.
        This test verifies that when newClientOrderId is provided, no broker prefix appears."""
        ex = create_safe_exchange('binance', apiKey='t', secret='t')
        cap = SignCapture(ex).install()
        clean_oid = 'clean_test_oid_123456'
        ex.sign('order', 'private', 'POST',
                {'symbol': 'BTCUSDT', 'side': 'BUY', 'type': 'LIMIT',
                 'quantity': '0.001', 'price': '50000', 'timeInForce': 'GTC',
                 'newClientOrderId': clean_oid})
        body = str(cap.last['body']) + str(cap.last['url'])
        for val in ('x-TKT5PX2F', 'x-cvBPrNm9', 'x-xcKtGhcu'):
            assert val not in body, f"Found broker prefix {val}"
        assert clean_oid in body


# ============================================================================
# Bybit: Referer header 必须消失
# ============================================================================

class TestBybit:
    def test_brokerId_none(self):
        ex = create_safe_exchange('bybit', apiKey='t', secret='t')
        assert ex.options.get('brokerId') is None

    def test_sign_no_referer(self):
        ex = create_safe_exchange('bybit', apiKey='t', secret='t')
        cap = SignCapture(ex).install()
        ex.sign('v5/order/create', 'private', 'POST', {'category': 'spot'})
        h = cap.last['headers']
        assert h.get('Referer') is None or h.get('Referer') == ''


# ============================================================================
# Audit hook 测试
# ============================================================================

class TestAuditHook:
    def test_dry_run_blocks_fetch(self):
        ex = create_safe_exchange('okx', apiKey='t', secret='t', password='t')
        enable_audit(ex, dry_run=True)
        with pytest.raises(AuditInterceptError):
            ex.fetch('https://example.com', 'GET', {}, None)

    def test_dry_run_captures_evidence(self):
        ex = create_safe_exchange('okx', apiKey='t', secret='t', password='t')
        enable_audit(ex, dry_run=True)
        try:
            ex.fetch('https://example.com', 'POST', {'X-Test': '1'}, '{}')
        except AuditInterceptError as e:
            assert e.method == 'POST'
            assert e.url == 'https://example.com'
            assert e.headers == {'X-Test': '1'}


# ============================================================================
# SafetyPolicy 测试
# ============================================================================

class TestSafetyPolicy:
    def test_default_strict_blocks_protected_key(self):
        """默认 strict 模式下，用户传入受保护 key 应被拒绝"""
        with pytest.raises(SafeBlockedError, match="touches protected key"):
            create_safe_exchange('okx', apiKey='t', secret='t', password='t',
                                options={'brokerId': 'my-custom-id'})

    def test_opt_in_allows_custom_broker(self):
        """allow_broker_opt_in=True 允许用户自定义 brokerId"""
        p = SafetyPolicy(allow_broker_opt_in=True)
        ex = create_safe_exchange('okx', apiKey='t', secret='t', password='t',
                                  policy=p, options={'brokerId': 'MY_OWN_TAG'})
        assert ex.options['brokerId'] == 'MY_OWN_TAG'

    def test_opt_in_rejects_ccxt_default_value(self):
        """即使 opt-in，也不能用 CCXT 默认 broker 值"""
        p = SafetyPolicy(allow_broker_opt_in=True)
        with pytest.raises(SafeBlockedError, match="known CCXT default"):
            create_safe_exchange('okx', apiKey='t', secret='t', password='t',
                                policy=p, options={'brokerId': '6b9ad766b55dBCDE'})

    def test_non_strict_defaults_to_warn(self):
        """非 strict 模式下 audit_on_findings 自动降为 warn"""
        p = SafetyPolicy(strict=False)
        assert p.audit_on_findings == 'warn'


# ============================================================================
# Scrubber 测试
# ============================================================================

class TestScrubber:
    def test_scrub_removes_empty_suspect_header(self):
        """scrubber 应删除值为空的可疑 header"""
        result = {
            'headers': {'X-BM-BROKER-ID': '', 'Content-Type': 'application/json'},
            'body': '', 'url': 'https://example.com',
        }
        _scrub_sign_result(result, 'bitmart', SafetyPolicy())
        assert 'X-BM-BROKER-ID' not in result['headers']
        assert 'Content-Type' in result['headers']

    def test_scrub_removes_known_broker_header(self):
        """scrubber 应删除值为已知 CCXT 默认值的 header"""
        result = {
            'headers': {'X-CHANNEL-API-CODE': 'p4sve'},
            'body': '', 'url': '',
        }
        _scrub_sign_result(result, 'bitget', SafetyPolicy())
        assert 'X-CHANNEL-API-CODE' not in result['headers']

    def test_scrub_keeps_user_header(self):
        """scrubber 不应删除用户自定义的非空非已知值 header"""
        result = {
            'headers': {'Referer': 'my-custom-referer'},
            'body': '', 'url': '',
        }
        _scrub_sign_result(result, 'bybit', SafetyPolicy())
        assert result['headers']['Referer'] == 'my-custom-referer'

    def test_scrub_removes_empty_body_tag(self):
        """scrubber 应从 JSON body 中删除空 tag 字段"""
        result = {
            'headers': {},
            'body': '{"tag":"","side":"buy","sz":"1"}',
            'url': '',
        }
        _scrub_sign_result(result, 'okx', SafetyPolicy())
        import json
        body = json.loads(result['body'])
        assert 'tag' not in body
        assert body['side'] == 'buy'

    def test_scrub_preserves_clientOrderId(self):
        """scrubber 不应删除 clientOrderId 类字段"""
        result = {
            'headers': {},
            'body': '{"clOrdId":"clean123","tag":""}',
            'url': '',
        }
        _scrub_sign_result(result, 'okx', SafetyPolicy())
        import json
        body = json.loads(result['body'])
        assert body['clOrdId'] == 'clean123'

    def test_scrub_disabled_by_policy(self):
        """scrub_empty_fields=False 时不清洗"""
        result = {
            'headers': {'X-BM-BROKER-ID': ''},
            'body': '', 'url': '',
        }
        _scrub_sign_result(result, 'bitmart', SafetyPolicy(scrub_empty_fields=False))
        assert 'X-BM-BROKER-ID' in result['headers']


# ============================================================================
# Hyperliquid 深层拦截测试
# ============================================================================

class TestHyperliquidDeepIntercept:
    def _make_hl(self):
        return create_safe_exchange('hyperliquid',
                                    walletAddress='0x' + '0' * 40,
                                    privateKey='0x' + 'a' * 64)

    def test_sign_blocks_approve_builder_fee_action(self):
        """sign() 应拦截 action.type=approveBuilderFee 的请求体"""
        import json
        ex = self._make_hl()
        body = json.dumps({'action': {'type': 'approveBuilderFee'}, 'nonce': 1})
        with pytest.raises(SafeBlockedError, match="approveBuilderFee"):
            ex.sign('exchange', 'private', 'POST', {}, None, body)

    def test_sign_blocks_set_referrer_action(self):
        """sign() 应拦截 action.type=setReferrer 的请求体"""
        import json
        ex = self._make_hl()
        body = json.dumps({'action': {'type': 'setReferrer'}, 'nonce': 1})
        with pytest.raises(SafeBlockedError, match="setReferrer"):
            ex.sign('exchange', 'private', 'POST', {}, None, body)

    def test_sign_allows_normal_action(self):
        """sign() 不应拦截正常 action（如 order）"""
        import json
        ex = self._make_hl()
        body = json.dumps({'action': {'type': 'order'}, 'nonce': 1})
        # Should not raise
        result = ex.sign('exchange', 'private', 'POST', {}, None, body)
        assert result is not None


# ============================================================================
# KuCoin scrubber 加固测试
# ============================================================================

class TestKuCoinScrubber:
    def test_scrubber_strips_partner_headers(self):
        """即使 sign() 产出了 KC-API-PARTNER header，scrubber 也会删除"""
        ex = create_safe_exchange('kucoin',
                                  apiKey='test', secret='test', password='test')
        enable_audit(ex, scrub=True)
        cap = SignCapture(ex).install()
        ex.sign('accounts', 'private', 'GET', {})
        h = cap.last['headers']
        assert 'KC-API-PARTNER' not in h

    def test_strict_rejects_partner_reinsertion(self):
        """strict 模式下，用户不能重新塞入 partner"""
        with pytest.raises(SafeBlockedError, match="touches protected key"):
            create_safe_exchange('kucoin',
                                apiKey='t', secret='t', password='t',
                                options={'partner': {'spot': {'id': 'x', 'key': 'y'}}})


# ============================================================================
# Scrubber + Audit 集成测试
# ============================================================================

class TestScrubberIntegration:
    def test_bitmart_header_scrubbed_after_sign(self):
        """bitmart sign() 产出的 X-BM-BROKER-ID 空值应被 scrubber 删除"""
        ex = create_safe_exchange('bitmart', apiKey='t', secret='t', uid='t')
        enable_audit(ex, scrub=True)
        cap = SignCapture(ex).install()
        ex.sign('spot/v1/submit_order', 'private', 'POST', {})
        h = cap.last['headers']
        assert h.get('X-BM-BROKER-ID') is None or 'X-BM-BROKER-ID' not in h
