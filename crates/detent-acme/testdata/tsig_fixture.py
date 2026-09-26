# /// script
# requires-python = ">=3.12"
# dependencies = ["dnspython==2.8.0"]
# ///
"""Check detent's TSIG fixtures with an independent implementation (dnspython).

Usage:
    uv run crates/detent-acme/testdata/tsig_fixture.py

No switches. Read-only: it prints to stdout and writes nothing.

It verifies the SIGNED request from src/tsig.rs tests with dnspython (this
raises on a bad MAC), prints the MAC dnspython read, and prints dnspython's
signed NOERROR and REFUSED answers to that request. These are the MAC,
ANSWER_OK and ANSWER_REFUSED constants in the tests.
"""

import unittest.mock as mock

import dns.message
import dns.name
import dns.rcode
import dns.tsig

TSIG_B64 = "ZGV0ZW50LXRzaWctdGVzdC1zZWNyZXQtMzItYnl0ZXM="
T = 1_700_000_000
SIGNED = bytes.fromhex(
    "123428000001000000020001076578616d706c6503636f6d00000600010f5f61636d652d63"
    "68616c6c656e6765076578616d706c6503636f6d00001000ff0000000000000f5f61636d65"
    "2d6368616c6c656e6765076578616d706c6503636f6d00001000010000003c00100f646967"
    "6573742d76616c75652d3432016b076578616d706c6503636f6d0000fa00ff00000000003d"
    "0b686d61632d7368613235360000006553f100012c002016d6dfbd1e1f23ed45663cd8efe2"
    "1233c1f64b2c616fa8034387f5532da75ab7123400000000"
)


def main() -> None:
    tsig = dns.tsig.Key("k.example.com.", TSIG_B64, "hmac-sha256.")
    ring = {dns.name.from_text("k.example.com."): tsig}
    with mock.patch("time.time", return_value=float(T)):
        query = dns.message.from_wire(SIGNED, keyring=ring)
    print("MAC", query.mac.hex())
    for name, rcode in [("OK", dns.rcode.NOERROR), ("REFUSED", dns.rcode.REFUSED)]:
        with mock.patch("time.time", return_value=float(T + 5)):
            answer = dns.message.make_response(query)
            answer.set_rcode(rcode)
            print("ANSWER_" + name, answer.to_wire().hex())


if __name__ == "__main__":
    main()
