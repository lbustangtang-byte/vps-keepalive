# -*- coding: utf-8 -*-
"""
aliyun-ecs-keepalive 本地/青龙版（Python 3.8+，零第三方依赖）

用途：按阿里云 CDT 累计互联网流量自动启停抢占式 ECS（香港）。
签名：阿里云 RPC 签名 V1 = HMAC-SHA1（不是 SHA256）。

环境变量：
    AK_ID  AK_SECRET  INSTANCE_ID                 必填
    REGION_ID            默认 cn-hongkong
    TRAFFIC_THRESHOLD_GB 默认 120
    TRAFFIC_LOW_GB       默认 0
    STOPPED_MODE         默认 StopCharging（节省停机）
    FAILSAFE_STOP        默认 0；1 = 流量查询失败时保守停机
    AUTO_START           默认 1；1 = 实例处于 Stopped/Stopping 且流量未超阈值时自动启动
                              （抢占式实例被阿里云回收后靠它拉起来）
    DRY_RUN              默认 0；1 = 只打印决策不调启停

用法：
    python keepalive.py            # 执行一次
    青龙：定时任务  python3 keepalive.py   每 3 分钟
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

DEFAULTS = {"REGION_ID": "cn-hongkong", "TRAFFIC_THRESHOLD_GB": 120,
            "TRAFFIC_LOW_GB": 0, "STOPPED_MODE": "StopCharging"}
STOPPED_MODE_MAP = {
    "节省停机": "StopCharging", "节省": "StopCharging", "economy": "StopCharging", "saving": "StopCharging",
    "普通停机": "KeepCharging", "普通": "KeepCharging", "normal": "KeepCharging", "standard": "KeepCharging",
    "stopcharging": "StopCharging", "keepcharging": "KeepCharging",
}


def log(level, msg, **data):
    rec = {"t": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "level": level, "msg": msg}
    if data:
        rec["data"] = data
    print(json.dumps(rec, ensure_ascii=False), flush=True)


def _enc(s):
    return quote(str(s), safe="~").replace("+", "%20").replace("*", "%2A")


def _sign(params, secret):
    canon = "&".join(f"{_enc(k)}={_enc(params[k])}" for k in sorted(params))
    s2s = "GET&%2F&" + _enc(canon)
    return base64.b64encode(hmac.new((secret + "&").encode(), s2s.encode(), hashlib.sha1).digest()).decode()


def call_api(endpoint, version, action, ak, sk, extra=None, retries=3):
    last = None
    for attempt in range(1, retries + 1):
        params = {
            "Format": "JSON", "Version": version, "AccessKeyId": ak,
            "SignatureMethod": "HMAC-SHA1",
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "SignatureVersion": "1.0", "SignatureNonce": uuid.uuid4().hex,
            "Action": action,
        }
        if extra:
            params.update(extra)
        params["Signature"] = _sign(params, sk)
        url = f"https://{endpoint}/?{urlencode(params)}"
        try:
            with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=20) as r:
                body = r.read().decode("utf-8", "replace")
            data = json.loads(body)
            if data.get("Code") and str(data["Code"]) != "200":
                raise RuntimeError(f"{action} 失败: {data.get('Code')} {data.get('Message')}")
            return data
        except Exception as e:  # noqa: BLE001
            last = e
            msg = str(e)
            if attempt < retries and any(k in msg for k in ("Throttling", "ServiceUnavailable", "timed out", "URLError")):
                time.sleep(2 ** (attempt - 1))
                continue
            raise
    raise last


def query_traffic_gb(ak, sk, region="cn-hongkong"):
    data = call_api("cdt.aliyuncs.com", "2021-08-13", "ListCdtInternetTraffic", ak, sk,
                    {"BusinessRegionId": region})
    details = data.get("TrafficDetails") or []
    total = sum(int(d.get("Traffic") or 0) for d in details)
    return total / (1024 ** 3), details


def describe(region, iid, ak, sk):
    data = call_api(f"ecs.{region}.aliyuncs.com", "2014-05-26", "DescribeInstances", ak, sk,
                    {"RegionId": region, "InstanceIds": json.dumps([iid])})
    lst = (data.get("Instances") or {}).get("Instance") or []
    if not lst:
        raise RuntimeError(f"未找到实例 {iid}（地域 {region}）")
    return lst[0]


def main():
    ak, sk, iid = os.getenv("AK_ID"), os.getenv("AK_SECRET"), os.getenv("INSTANCE_ID")
    if not (ak and sk and iid):
        log("ERROR", "缺少环境变量 AK_ID / AK_SECRET / INSTANCE_ID")
        return 1
    region = os.getenv("REGION_ID") or DEFAULTS["REGION_ID"]
    thr = float(os.getenv("TRAFFIC_THRESHOLD_GB") or DEFAULTS["TRAFFIC_THRESHOLD_GB"])
    low = float(os.getenv("TRAFFIC_LOW_GB") or DEFAULTS["TRAFFIC_LOW_GB"])
    mode_raw = (os.getenv("STOPPED_MODE") or DEFAULTS["STOPPED_MODE"]).strip()
    mode = STOPPED_MODE_MAP.get(mode_raw.lower(), STOPPED_MODE_MAP.get(mode_raw, mode_raw))
    failsafe = os.getenv("FAILSAFE_STOP", "0") == "1"
    auto_start = os.getenv("AUTO_START", "1") == "1"
    dry = os.getenv("DRY_RUN", "0") == "1"

    log("INFO", "keepalive 开始", region=region, instance=iid, thresholdGB=thr, lowGB=low, mode=mode, dry=dry)
    try:
        inst = describe(region, iid, ak, sk)
    except Exception as e:  # noqa: BLE001
        log("ERROR", "实例查询失败", err=str(e))
        return 1
    status = inst.get("Status")
    log("INFO", "实例状态", id=inst.get("InstanceId"), status=status, type=inst.get("InstanceType"))

    try:
        gb, details = query_traffic_gb(ak, sk, region)
        log("INFO", "CDT 累计流量", totalGB=round(gb, 3), items=len(details))
    except Exception as e:  # noqa: BLE001
        log("ERROR", "CDT 流量查询失败", err=str(e))
        if failsafe and status == "Running" and not dry:
            log("WARN", "FAILSAFE_STOP=1，保守停机")
            call_api(f"ecs.{region}.aliyuncs.com", "2014-05-26", "StopInstance", ak, sk,
                     {"InstanceId": iid, "StoppedMode": mode, "ForceStop": "true"})
            log("INFO", "已发送停机")
        return 1

    over, under = gb >= thr, gb <= low
    log("INFO", "决策", over=over, under=under, totalGB=round(gb, 3))

    try:
        if over and status != "Stopped":
            if status == "Starting":
                log("WARN", "启动中，跳过")
            elif dry:
                log("INFO", "[DRY_RUN] 将停机")
            else:
                call_api(f"ecs.{region}.aliyuncs.com", "2014-05-26", "StopInstance", ak, sk,
                         {"InstanceId": iid, "StoppedMode": mode, "ForceStop": "true"})
                log("INFO", "已停机（超阈值）", mode=mode)
        elif auto_start and status in ("Stopped", "Stopping") and gb < thr:
            if status == "Stopping":
                log("WARN", "停机中，跳过")
            elif dry:
                log("INFO", "[DRY_RUN] 将启动")
            else:
                call_api(f"ecs.{region}.aliyuncs.com", "2014-05-26", "StartInstance", ak, sk, {"InstanceId": iid})
                log("INFO", "已启动（低于低水位）")
        else:
            log("INFO", "无需动作", status=status)
    except Exception as e:  # noqa: BLE001
        log("ERROR", "启停失败", err=str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
