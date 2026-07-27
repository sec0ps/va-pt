"""Flask app factory and waitress serve helper."""

import os

from flask import Flask

from console import auth
from console.routes import ui


def create_app(config, worker, scheduler):
    base = os.path.dirname(__file__)
    app = Flask(
        __name__,
        template_folder=os.path.join(base, "templates"),
        static_folder=os.path.join(base, "static"),
    )
    app.secret_key = config.console_secret()
    app.config["APP_CONFIG"] = config
    app.config["WORKER"] = worker
    app.config["SCHEDULER"] = scheduler
    app.register_blueprint(ui)

    @app.context_processor
    def inject_user():
        return {"current_user": auth.current_user()}

    return app


def serve(app, bind):
    from waitress import serve as waitress_serve

    host, _, port = bind.partition(":")
    waitress_serve(app, host=host or "0.0.0.0", port=int(port or "8080"))
