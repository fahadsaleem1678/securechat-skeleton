# app/client.py  (Phase-4 ready) -- replay option added (no other logic changed)
import socket
import os
import base64
import json
import time
from app.common import protocol as proto
from app.crypto import pki, dh as dhmod, aes as aesmod
from app.crypto import sign as signmod

CERTS_DIR = "certs"
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.cert.pem")
CLIENT_CERT_PATH = os.path.join(CERTS_DIR, "client.local.cert.pem")
CLIENT_KEY_PATH = os.path.join(CERTS_DIR, "client.local.key.pem")

HOST = "127.0.0.1"
PORT = 9000

def do_handshake(f, ca_cert, client_pem):
    nonce = base64.b64encode(os.urandom(16)).decode()
    hello = {"type": "hello", "client_cert": client_pem, "nonce": nonce}
    f.write(proto.pack_message(hello)); f.flush()

    line = f.readline()
    resp = proto.unpack_message(line)
    if resp.get("type") == "bad_cert":
        raise Exception("server rejected client cert: " + str(resp.get("reason")))
    server_pem = resp.get("server_cert")
    server_cert = pki.load_cert_pem_bytes(server_pem.encode())
    pki.verify_certificate_chain(server_cert, ca_cert, expected_hostname="server.local")

    # DH
    p = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
    g = 5
    a = dhmod.gen_dh_private()
    A = dhmod.compute_public(g, a, p)
    f.write(proto.pack_message({"type":"dh_client","p": str(p), "g": str(g), "A": str(A)})); f.flush()

    line = f.readline()
    dh_resp = proto.unpack_message(line)
    B = int(dh_resp["B"])
    Ks = dhmod.compute_shared_secret(B, a, p)
    K = dhmod.ks_to_aes128_key(Ks)
    # read handshake_complete
    f.readline()
    return K, server_cert

def sign_message(priv_key, seqno: int, ts: int, ct_b64: str) -> str:
    hash_input = f"{seqno}|{ts}|{ct_b64}".encode()
    return signmod.rsa_sign(priv_key, hash_input)

def send_encrypted_and_receive(f, K: bytes, payload: dict, seqno: int, client_priv=None):
    """
    Encrypt payload to ct_b64, sign seqno|ts|ct_b64 with client_priv (if provided),
    send outer envelope {type:enc, seqno, ct, ts, sig}
    """
    pt = json.dumps(payload, separators=(",", ":")).encode()
    ct = aesmod.encrypt_ecb_pkcs7(K, pt)
    ct_b64 = aesmod.b64enc(ct)
    ts = int(time.time() * 1000)
    sig_b64 = None
    if client_priv is not None:
        sig_b64 = sign_message(client_priv, seqno, ts, ct_b64)
    outer = {"type":"enc", "seqno": seqno, "ct": ct_b64, "ts": ts, "sig": sig_b64}
    f.write(proto.pack_message(outer)); f.flush()
    line = f.readline()
    if not line:
        return None
    return proto.unpack_message(line)

def main():
    ca_cert = pki.load_cert_from_file(CA_CERT_PATH)
    with open(CLIENT_CERT_PATH, "rb") as f:
        client_pem = f.read().decode()

    # load client private key for signing messages
    try:
        client_priv = signmod.load_private_key(CLIENT_KEY_PATH)
    except Exception as e:
        print("[-] failed to load client private key:", e)
        client_priv = None

    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb")
    try:
        (K, server_cert) = do_handshake(f, ca_cert, client_pem)
        print("[*] session key derived (hex):", K.hex())
        seqno = 1
        logged_in = False
        username = None

        while True:
            print("\nChoose: 1) register  2) login  3) quit")
            c = input("Choice> ").strip()
            if c == "1":
                email = input("email> ").strip()
                username = input("username> ").strip()
                password = input("password> ").strip()
                payload = {"type":"register","email":email,"username":username,"password":password}
                resp = send_encrypted_and_receive(f, K, payload, seqno, client_priv); seqno += 1
                print("server ->", resp)

            elif c == "2":
                email = input("email> ").strip()
                password = input("password> ").strip()
                payload = {"type":"login","email":email,"password":password}
                resp = send_encrypted_and_receive(f, K, payload, seqno, client_priv); seqno += 1
                print("server ->", resp)
                if resp and resp.get("ok"):
                    print("[+] logged in as", resp.get("username"))
                    logged_in = True
                    username = resp.get("username")

                    # chat loop
                    while logged_in:
                        # <-- replay option added here only (no other logic changed)
                        print("\nChat: 1) send message  2) end session (get receipt)  3) logout  4) replay last seqno")
                        ch = input("Chat> ").strip()
                        if ch == "1":
                            text = input("Message> ").strip()
                            payload = {"type":"msg","text": text}
                            resp = send_encrypted_and_receive(f, K, payload, seqno, client_priv); seqno += 1
                            print("server ->", resp)

                        elif ch == "2":
                            payload = {"type":"end_session"}
                            resp = send_encrypted_and_receive(f, K, payload, seqno, client_priv); seqno += 1
                            print("server ->", resp)
                            # server sends plaintext receipt JSON (not encrypted)
                            if resp and resp.get("type") == "receipt":
                                server_receipt = resp
                                hex_hash = server_receipt.get("transcript_sha256")
                                sig = server_receipt.get("sig")
                                if sig:
                                    try:
                                        server_pub = server_cert.public_key()
                                        ok = signmod.rsa_verify(server_pub, bytes.fromhex(hex_hash), sig)
                                        print("[*] server receipt signature valid:", ok)
                                    except Exception as e:
                                        print("[-] failed to verify server signature:", e)
                                else:
                                    print("[-] server did not provide signature")

                                # create client receipt and save locally
                                if client_priv:
                                    client_sig = signmod.rsa_sign(client_priv, bytes.fromhex(hex_hash))
                                else:
                                    client_sig = None
                                client_receipt = {
                                    "type": "receipt",
                                    "peer": "client",
                                    "first_seq": server_receipt.get("first_seq", 0),
                                    "last_seq": server_receipt.get("last_seq"),
                                    "transcript_sha256": hex_hash,
                                    "sig": client_sig
                                }
                                os.makedirs("transcripts", exist_ok=True)
                                path = os.path.join("transcripts", f"receipt_client_{int(time.time()*1000)}.json")
                                with open(path, "w", encoding="utf-8") as rf:
                                    json.dump(client_receipt, rf, separators=(",",":"))
                                print("[*] saved client receipt to", path)
                            else:
                                print("[-] unexpected server response for end_session:", resp)

                        elif ch == "3":
                            logged_in = False
                            print("[*] logged out")

                        # Replay option: resend previous seqno (do NOT increment seqno)
                        elif ch == "4":
                            # only attempt a replay if there is a previous seq to reuse
                            if seqno <= 1:
                                print("[-] no previous seqno to replay")
                            else:
                                old_seq = seqno - 1
                                print(f"[*] sending replay with seqno={old_seq} (expect server to respond with REPLAY)")
                                # send a small test payload (message) with old_seq; do NOT increment seqno
                                payload = {"type":"msg","text":"REPLAY_TEST"}
                                resp = send_encrypted_and_receive(f, K, payload, old_seq, client_priv)
                                print("server ->", resp)

                        else:
                            print("invalid chat option")

            elif c == "3":
                print("quitting")
                break
            else:
                print("invalid choice")
    finally:
        try:
            f.close()
        except:
            pass
        s.close()

if __name__ == "__main__":
    main()
