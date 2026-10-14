"""Initialize the server and emit an enrollment code for the setup wizard."""

import contextlib
import getpass
import io
import json
import platform
import sys
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))


def main() -> int:
    enroll_local_agent = len(sys.argv) > 1 and sys.argv[1].lower() == "both"

    with contextlib.redirect_stdout(io.StringIO()):
        from api.app import create_app
        from api.auth import get_or_create_admin_token
        from clipboard_engine.device_credentials import save_device_credentials

        app = create_app()
        admin_token = get_or_create_admin_token()
        with app.test_client() as client:
            code_response = client.post(
                "/api/v1/devices/enrollment-codes",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"expires_minutes": 10},
            )
            if code_response.status_code != 201:
                raise RuntimeError("Could not create the initial enrollment code.")
            enrollment_code = code_response.get_json()["code"]

            if enroll_local_agent:
                enrollment = client.post(
                    "/api/v1/devices/enroll",
                    json={
                        "code": enrollment_code,
                        "hostname": platform.node() or "unknown-host",
                        "os_user": getpass.getuser(),
                    },
                )
                if enrollment.status_code != 201:
                    raise RuntimeError("Could not enroll this PC as a local agent.")
                credentials = enrollment.get_json()
                save_device_credentials(
                    credentials["device_id"], credentials["device_token"]
                )

                remote_code = client.post(
                    "/api/v1/devices/enrollment-codes",
                    headers={"Authorization": f"Bearer {admin_token}"},
                    json={"expires_minutes": 10},
                )
                if remote_code.status_code != 201:
                    raise RuntimeError("Could not create a remote enrollment code.")
                enrollment_code = remote_code.get_json()["code"]

    print(json.dumps({"enrollment_code": enrollment_code}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)