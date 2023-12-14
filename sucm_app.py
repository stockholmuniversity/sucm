from sucm import create_app
from sucm.sucm_automation import start_scheduler

app = create_app()

if __name__ == '__main__':
    start_scheduler()  # Start the scheduler
    app.run(debug=True)
