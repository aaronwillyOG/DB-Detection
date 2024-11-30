import psutil

def monitor_processes():
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
        try:
            print(proc.info)
            if proc.info['cpu_percent'] > 50: 
                print(f"High CPU usage detected: {proc.info}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

if __name__ == '__main__':
    monitor_processes()
