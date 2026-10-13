from txwarden.models import Tx
from txwarden.simulator import AnvilSimulator, decode_calldata


def w(n):
    return f"{n:064x}"


def test_decode_approve():
    data = "0x095ea7b3" + w(0xABCD) + w(2**256 - 1)
    d = decode_calldata(data)
    assert d["kind"] == "approve" and d["amount"] == 2**256 - 1
    assert d["spender"].endswith("abcd")


def test_decode_v2_swap():
    t_in, t_out = 0x1111, 0x2222
    data = ("0x38ed1739" + w(1000) + w(900) + w(0xA0) + w(0xBEEF) + w(9999)
            + w(2) + w(t_in) + w(t_out))
    d = decode_calldata(data)
    assert d["kind"] == "v2_swap" and d["amount_in"] == 1000 and d["min_out"] == 900
    assert [p[-4:] for p in d["path"]] == ["1111", "2222"]


def test_decode_unknown():
    assert decode_calldata("0xdeadbeef")["kind"] == "unknown"


def test_anvil_simulator_approve_with_mock_rpc():
    def rpc(method, params):
        return {"eth_call": "0x", "eth_estimateGas": hex(46000)}[method]

    sim = AnvilSimulator(transport=rpc)
    tx = Tx("0x" + "11" * 20, "0x" + "cc" * 20, "0x095ea7b3" + w(0xABCD) + w(5))
    r = sim.simulate(tx)
    assert r.success and r.gas_used == 46000 and r.approvals[0].amount == 5


def test_anvil_simulator_reports_revert():
    def rpc(method, params):
        raise RuntimeError("execution reverted: EXPIRED")

    r = AnvilSimulator(transport=rpc).simulate(Tx("0x" + "11" * 20, "0x" + "cc" * 20))
    assert not r.success and "EXPIRED" in r.revert_reason


def test_anvil_simulator_swap_reserves_ordering():
    t_in, t_out = 0x2222, 0x1111  # t_in > t_out, so reserves are (r1, r0) for (in, out)
    pair = "0x" + "99" * 20

    def rpc(method, params):
        if method == "eth_estimateGas":
            return hex(150000)
        data = params[0]["data"]
        if data.startswith("0xe6a43905"):
            return "0x" + w(int(pair, 16))
        if data.startswith("0x0902f1ac"):
            return "0x" + w(5000) + w(7000) + w(0)
        return "0x"

    data = ("0x38ed1739" + w(10) + w(9) + w(0xA0) + w(0xBEEF) + w(9999) + w(2) + w(t_in) + w(t_out))
    r = AnvilSimulator(transport=rpc).simulate(Tx("0x" + "11" * 20, "0x" + "77" * 20, data))
    assert r.swap.reserve_in == 7000 and r.swap.reserve_out == 5000
