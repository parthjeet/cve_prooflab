"""Small user lookup service."""
import logging

import db

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 20


def show_user(name):
    logger.info("looking up user")
    rows = db.find_user(name)
    return rows[: DEFAULT_LIMIT]


def show_orders(user_id):
    return db.list_orders(user_id)
