import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, request, jsonify
import threading
import signal


app = Flask(__name__)

modified_files = [] 

class Watcher:
    def __init__(self, directory_to_watch):
        self.observer = Observer()
        self.directory_to_watch = directory_to_watch

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.directory_to_watch, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        print(f"File modified: {event.src_path}")
        modified_files.append(event.src_path)  # Add to modified files list

    def on_created(self, event):
        if event.is_directory:
            return
        print(f"File created: {event.src_path}")
        modified_files.append(event.src_path)  # Add to modified files list

    def on_deleted(self, event):
        if event.is_directory:
            return
        print(f"File deleted: {event.src_path}")
        modified_files.append(event.src_path)  # Add to modified files list

    def on_moved(self, event):
        if event.is_directory:
            return
        print(f"File moved: {event.src_path}")
        modified_files.append(event.src_path)  # Add to modified files list

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    directory_to_watch = request.json.get('directory')
    
    if not os.path.isdir(directory_to_watch):
        return jsonify({'error': 'Directory not found or invalid path'}), 400

    
    threading.Thread(target=start_watcher, args=(directory_to_watch,)).start()
    
    return jsonify({'message': f'Started monitoring directory: {directory_to_watch}'}), 200

def start_watcher(directory_to_watch):
    watcher = Watcher(directory_to_watch)
    watcher.run()

@app.route('/get_modified_files', methods=['GET'])
def get_modified_files():
    
    return jsonify({'modified_files': modified_files})

@app.route('/shutdown', methods=['POST'])
def shutdown():
    pid = os.getpid()
    os.kill(pid, signal.SIGINT)
    return 'Server shutting down...'


if __name__ == '__main__':
    
    app.run()