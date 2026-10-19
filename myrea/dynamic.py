import frida
import sys
import time
import json

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        try:
            event = json.loads(payload)
            print(f"[!] {event['type']}: {event['target']}")
        except:
            print(f"[*] {payload}")

def run_dynamic_analysis(exe_path, vm_ip):
    print(f"[*] Connecting to Frida server at {vm_ip}...")
    try:
        device = frida.get_device_manager().add_remote_device(f"{vm_ip}:27042")
        pid = device.spawn([exe_path])
        session = device.attach(pid)
        with open("myrea/dynamic_hook.js", "r") as f:
            js_code = f.read()
        script = session.create_script(js_code)
        script.on('message', on_message)
        script.load()
        device.resume(pid)
        print("[*] Process running. Monitoring for 10 seconds...")
        time.sleep(10)
        session.detach()
        device.kill(pid)
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python myrea/dynamic.py <path_to_exe_on_windows> <vm_ip_address>")
        sys.exit(1)
    run_dynamic_analysis(sys.argv[1], sys.argv[2])
