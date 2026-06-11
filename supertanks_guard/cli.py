"""Human side of the gate: approve/deny pending actions from the terminal.

The whole point of GO-GATE is that the approving human is NOT the agent.
This CLI is that human's tool.
"""
import argparse
import json
import sys

from supertanks_guard import audit, gate


def main() -> None:
    p = argparse.ArgumentParser(
        prog="supertanks-guard",
        description="Approve or deny actions requested by your AI agent.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pending", help="list actions waiting for your decision")
    for name in ("approve", "deny"):
        sp = sub.add_parser(name, help=f"{name} a pending action")
        sp.add_argument("tx_id")
    audit_p = sub.add_parser("audit", help="show recent audit entries + chain check")
    audit_p.add_argument("--limit", type=int, default=20)

    a = p.parse_args()
    if a.cmd == "pending":
        rows = gate.pending()
        if not rows:
            print("No pending actions.")
            return
        for r in rows:
            print(f"{r['tx_id']}  [{r['risk']:6}] {r['action']}  "
                  f"(expires in {r['expires_in']}s)\n    {r['params']}")
    elif a.cmd in ("approve", "deny"):
        res = gate.decide(a.tx_id, approve=(a.cmd == "approve"))
        audit.record("human_decision", {"tx_id": a.tx_id, "decision": a.cmd,
                                        "ok": res.get("ok", False)})
        print(json.dumps(res, ensure_ascii=False))
        if not res.get("ok"):
            sys.exit(1)
    elif a.cmd == "audit":
        print(json.dumps({"chain": audit.verify_chain(),
                          "entries": audit.tail(a.limit)},
                         indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
