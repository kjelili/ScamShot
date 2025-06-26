import schedule
import time

def retrain_model():
    print("Retraining Scamshot model...")  # Placeholder for actual retraining

schedule.every().day.at("02:00").do(retrain_model)

if __name__ == "__main__":
    while True:
        schedule.run_pending()
        time.sleep(60)
