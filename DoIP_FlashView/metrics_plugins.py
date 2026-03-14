# metrics_plugins.py
METRIC_REGISTRY = {}

def register_metric(fn):
    METRIC_REGISTRY[fn.__name__] = fn
    return fn

@register_metric
def verify_time_routine(events_range, params):
    rid = params["routine_id"]
    sfn_start = params["start_subfn"]
    sfn_end = params["end_subfn"]
    ok = params["ok_info"]
    start = None
    for e in events_range:
        if e.get("rc_id") == rid and e.get("rc_subfn") == sfn_start and e["uds_reply"] == 0x00:
            start = e
            break
    if start:
        for e in events_range:
            if e["frame"] <= start["frame"]:
                continue
            if e.get("rc_id") == rid and e.get("rc_subfn") == sfn_end and e["uds_reply"] == 0x01 and e.get("rc_info") == ok:
                return e["t_epoch"] - start["t_epoch"]
    return None

@register_metric
def verify_time_did(events_range, params):
    dids = params["dids"]
    for did in dids:
        start = None
        for e in events_range:
            if e["uds_sid"] == 0x22 and e["uds_reply"] == 0x00 and e.get("rdbi_did") == did:
                start = e
                break
        if start:
            for e in events_range:
                if e["frame"] <= start["frame"]:
                    continue
                if e["uds_sid"] == 0x22 and e["uds_reply"] == 0x01 and e["uds_err_code"] is None and e.get("rdbi_did") == did:
                    return e["t_epoch"] - start["t_epoch"]
    return None