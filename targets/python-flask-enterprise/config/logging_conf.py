"""Centralised logging setup."""
import logging
import logging.config


def init_logging(app):
    logging.config.dictConfig({
        "version": 1,
        "formatters": {
            "standard": {
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "level": "INFO",
            },
        },
        "root": {"handlers": ["console"], "level": "INFO"},
    })
    app.logger.info("logging initialised")
