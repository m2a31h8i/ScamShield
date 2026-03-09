from queue import Queue
import threading

task_queue = Queue()

def worker():
    while True:
        task = task_queue.get()

        try:
            func, args = task
            func(*args)
        except Exception as e:
            print("Task Error:", e)

        task_queue.task_done()

thread = threading.Thread(target=worker, daemon=True)
thread.start()

def add_task(func, *args):
    task_queue.put((func, args))