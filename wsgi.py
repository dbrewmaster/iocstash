from portal import app, scheduler

if not scheduler.running:
    scheduler.start()
    print("[✔] Scheduler started")

application = app
