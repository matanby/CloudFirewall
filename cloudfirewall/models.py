from wtforms import StringField, validators


class User(object):
    """
    Represent user in the system
    """
    username = StringField('Username', [validators.DataRequired()])

    def __init__(self, username):
        self.username = username
        self.authenticated = False

    def is_authenticated(self):
        return self.authenticated

    def set_authenticated(self, authenticated):
        self.authenticated = authenticated

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.username)
