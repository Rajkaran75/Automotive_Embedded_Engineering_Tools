# config.py
CORE_METRICS = [
    {"id": "component", "name": "Component #", "width": 100},
    {"id": "start_frame", "name": "Start Frame", "width": 110},
    {"id": "end_frame", "name": "End Frame", "width": 110},
    {"id": "total_time", "name": "Total Time (s)", "width": 120},
    {"id": "reqdl_time", "name": "ReqDL Time (s)", "width": 130},
    {"id": "reqdl_pending", "name": "ReqDL Pending (s)", "width": 140},
    {"id": "transfer_time", "name": "Transfer Time (s)", "width": 140},
    {"id": "td_pending", "name": "TD Pending (s)", "width": 130},
    {"id": "transfer_exit_time", "name": "TransferExit Time (s)", "width": 120},
    {"id": "other_uds_services_post_transfer_exit", "name": "Other UDS Post Transfer Exit", "width": 250},
]

PROFILE_MINIMAL = {
    "id": "core_uds_only",
    "name": "Core UDS Only (No Verify)",
    "extended_metrics": []
}

BUILTIN_PROFILES = [PROFILE_MINIMAL]











# # config.py
# CORE_METRICS = [
#     {"id": "component", "name": "Component #", "width": 100},
#     {"id": "start_frame", "name": "Start Frame", "width": 110},
#     {"id": "end_frame", "name": "End Frame", "width": 110},
#     {"id": "total_time", "name": "Total Time (s)", "width": 120},
#     {"id": "reqdl_time", "name": "ReqDL Time (s)", "width": 130},
#     {"id": "reqdl_pending", "name": "ReqDL Pending (s)", "width": 140},
#     {"id": "transfer_time", "name": "Transfer Time (s)", "width": 140},
#     {"id": "td_pending", "name": "TD Pending (s)", "width": 130},
#     {"id": "transfer_exit_time", "name": "Exit Time (s)", "width": 120},
#     {"id": "other_uds_services_post_transfer_exit", "name": "Other UDS Post Exit", "width": 250},
# ]

# PROFILE_MINIMAL = {
#     "id": "core_uds_only",
#     "name": "Core UDS Only (No Verify)",
#     "extended_metrics": []
# }

# PROFILE_ROUTINE_F002 = {
#     "id": "verify_routine_f002",
#     "name": "With RoutineControl F002 Verify",
#     "extended_metrics": [
#         {
#             "id": "verify_time",
#             "name": "Verify Time (s)",
#             "width": 130,
#             "compute_fn": "verify_time_routine",
#             "params": {"routine_id": 0xF002, "start_subfn": 0x01, "end_subfn": 0x03, "ok_info": 0x00}
#         }
#     ]
# }

# BUILTIN_PROFILES = [PROFILE_MINIMAL, PROFILE_ROUTINE_F002]