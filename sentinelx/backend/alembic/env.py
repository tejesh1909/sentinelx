from alembic import context
from app.core import engine, Base
from app import models  # noqa
with engine.connect() as c:
    context.configure(connection=c, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
