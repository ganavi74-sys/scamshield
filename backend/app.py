from flask import Flask
from flask_cors import CORS
from routes.analysis import analysis_bp

app = Flask(__name__)

CORS(app)

app.register_blueprint(analysis_bp)


@app.route("/")
def home():
    return "ScamShield backend is running!"


if __name__ == "__main__":
    app.run(debug=True)