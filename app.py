from flask import Flask, render_template, request
from analyzer import analyze_message
from database import init_db, save_scan, get_recent_scans

app = Flask(__name__)

init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message:
            result = analyze_message(message)
            save_scan(message, result)
        else:
            result = {
                "score": 0,
                "risk": "No message",
                "reasons": ["Please enter a message."],
                "prediction": "No prediction",
                "confidence": 0.0
            }

    history = get_recent_scans()

    return render_template(
        "index.html",
        result=result,
        message=message,
        history=history
    )


if __name__ == "__main__":
    app.run(debug=True)