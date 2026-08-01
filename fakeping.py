import subprocess

result = subprocess.run(
    ['ping', '192.168.1.0'],
    capture_output=True,
    text=True
)

print(result.returncode)
print(result.stdout)