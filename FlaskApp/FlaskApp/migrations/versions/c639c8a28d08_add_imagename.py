"""add imagename

Revision ID: c639c8a28d08
Revises: 6ee7240ca48a
Create Date: 2019-04-13 15:44:59.028961

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c639c8a28d08'
down_revision = '6ee7240ca48a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('products', sa.Column('imgname', sa.String(length=60), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('products', 'imgname')
    # ### end Alembic commands ###
