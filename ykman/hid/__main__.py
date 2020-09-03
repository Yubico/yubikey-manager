from . import list_devices
from .base import ManagementApplication, YkCfgApplication


for dev in list_devices():
    with dev.open_otp_connection() as conn:
        print("Version", tuple(conn.read_feature_report()[2:5]))
        app = ManagementApplication(conn)
        print("Device info:", app.read_device_info().hex())

    with dev.open_otp_connection() as conn:
        app = YkCfgApplication(conn)
        from threading import Timer, Event

        event = Event()
        Timer(3, event.set).start()
        resp = app.calculate_hmac_sha1(b"\1\2\3\4\5\6\7\0", 2, event, print)
        print("response", resp.hex())

        app.set_hmac_sha1_secret(b"\1\3\2\4\5\6\7\0", 2, True)
        resp = app.calculate_hmac_sha1(b"\1\2\3\4\5\6\7\0", 2)
        print("response", resp.hex())
