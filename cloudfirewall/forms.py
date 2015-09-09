from wtforms import Form, StringField, PasswordField, validators
from models import User
import config


class LoginForm(Form):
	username = StringField('Username', [validators.DataRequired()])
	password = PasswordField('Password', [validators.DataRequired()])

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.user = None

	def validate(self):
		rv = Form.validate(self)
		if not rv:
			return False

		user = User(self.username.data)

		if user.username != config.ADMIN_USERNAME:
			self.username.errors.append('Invalid username')
			return False

		if self.password.data != config.ADMIN_PASSWORD:
			self.password.errors.append('Invalid password')
			return False

		self.user = user
		return True
