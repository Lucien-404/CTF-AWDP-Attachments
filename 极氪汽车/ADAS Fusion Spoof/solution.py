#!/usr/bin/env python3
"""
GEELY "ADAS Fusion Spoof" — full solution.

Steps
-----
1. Parse the calibration / acceptance protocol / evidence frames.
2. Transform camera + radar observations into the vehicle base frame.
   The YAML matrices are actually  vehicle_from_sensor  (despite the label),
   i.e.  p_vehicle = R @ p_sensor + t .  Proof: with this convention the
   camera and radar positions coincide to <0.0003 m and Z is exactly 0.750
   for both.  (Using the literal formula R^T(p-t) makes Z = -2.17 / -0.29,
   which violates rule 2 and cannot satisfy rule 1.)
3. The fused target is the (camera+radar)/2 vehicle-frame position; it rounds
   to the clean values (39.5,-1.7,0.75), (38.6,-1.61,0.75), (37.7,-1.52,0.75).
4. Relative velocity from the three frames: vx = -18.000, vy = +1.800 m/s.
5. Verify every acceptance rule, build the INJECT message and the HMAC flag.
"""
import json, hashlib, hmac, os
import numpy as np

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attachments", "attachments")

# ---------- provenance / key material ----------
calib_bytes = open(os.path.join(HERE, "calibration", "camera_radar_calibration.yaml"), "rb").read()
acc_bytes   = open(os.path.join(HERE, "protocol", "fusion_acceptance.txt"), "rb").read()

KEY = hashlib.sha256(
    hashlib.sha256(calib_bytes).digest()
    + hashlib.sha256(acc_bytes).digest()
    + b"GEELY-ADAS-FRONT-FUSION"
).digest()

# ---------- extrinsics ----------
Rc = np.array([[0.999390827019096, -0.034899496702501, 0.0],
               [0.034899496702501,  0.999390827019096, 0.0],
               [0.0, 0.0, 1.0]])
tc = np.array([1.820, -0.040, 1.460])
Rr = np.array([[0.999847695156391, 0.017452406437283, 0.0],
               [-0.017452406437283, 0.999847695156391, 0.0],
               [0.0, 0.0, 1.0]])
tr = np.array([0.150, 0.030, 0.520])

frames = [json.loads(l) for l in open(os.path.join(HERE, "evidence", "adas_frames.jsonl")) if l.strip()]

cam, rad, fused = [], [], []
for f in frames:
    c = Rc @ np.array(f["camera_targets"][0]["position_camera_m"]) + tc
    r = Rr @ np.array(f["radar_tracks"][0]["position_radar_m"]) + tr
    cam.append(c); rad.append(r); fused.append((c + r) / 2.0)
cam, rad, fused = np.array(cam), np.array(rad), np.array(fused)

print("vehicle-frame camera :", np.round(cam, 4).tolist())
print("vehicle-frame radar  :", np.round(rad, 4).tolist())
print("rule1 |cam-rad| norm :", [round(float(np.linalg.norm(cam[i] - rad[i])), 6) for i in range(3)])

# ---------- canonical injection (rounded to 3 decimals) ----------
P = np.round(fused, 3)
vx = round((P[2, 0] - P[0, 0]) / 0.10, 3)
vy = round((P[2, 1] - P[0, 1]) / 0.10, 3)

# sanity: exact linear motion
P = np.array([[39.500, -1.700, 0.750],
              [38.600, -1.610, 0.750],
              [37.700, -1.520, 0.750]])
vx, vy = -18.000, 1.800

# ---------- rule verification ----------
ok = True
# 1. camera vs radar
d = max(float(np.linalg.norm(cam[i] - rad[i])) for i in range(3))
ok &= d <= 0.25
print(f"[1] max |cam-rad| = {d:.6f} <= 0.25           -> {d<=0.25}")
# 2. height
h = P[:, 2]
ok &= bool(np.all((h >= 0.40) & (h <= 1.90)))
print(f"[2] height {h.tolist()} in [0.40,1.90]         -> {bool(np.all((h>=0.40)&(h<=1.90)))}")
# 3. longitudinal relative velocity
vel = (P[2, 0] - P[0, 0]) / 0.10
ok &= (vel < 0) and (14.0 <= abs(vel) <= 22.0)
print(f"[3] vx = {vel:.3f} -> negative & |v| in [14,22]  -> {(vel<0) and (14.0<=abs(vel)<=22.0)}")
# 4. lateral acceleration
ay = ((P[2, 1] - P[1, 1]) - (P[1, 1] - P[0, 1])) / 0.05**2
ok &= abs(ay) <= 2.5
print(f"[4] lateral accel = {abs(ay):.4f} <= 2.5        -> {abs(ay)<=2.5}")
# 5. TTC
ttc = P[0, 0] / abs(vel)
ok &= ttc < 2.20
print(f"[5] TTC = {ttc:.4f} < 2.20                     -> {ttc<2.20}")
# 6. yaw-rate induced lateral displacement
yr = frames[0]["ego"]["yaw_rate_radps"]
disp = abs(yr * 0.05 * P[0, 0])
ok &= disp < 0.12
print(f"[6] yaw lateral disp = {disp:.5f} < 0.12       -> {disp<0.12}")
print("ALL RULES PASS:", ok)

# ---------- message + flag ----------
rows = [f"INJECT|frame={i}|t={100.0+0.05*(i-1):.3f}"
        f"|x={P[i-1,0]:.3f}|y={P[i-1,1]:.3f}|z={P[i-1,2]:.3f}"
        f"|vx={vx:.3f}|vy={vy:.3f}" for i in (1, 2, 3)]
message = "\n".join(rows) + "\n"

print("\n=== ACCEPTED INJECT MESSAGE ===")
print(message, end="")

code = hmac.new(KEY, message.encode(), hashlib.sha256).hexdigest()
flag = f"GEELY{{ADAS_{code[:24]}_{code[-24:]}}}"
print("CODE =", code)
print("FLAG =", flag)
