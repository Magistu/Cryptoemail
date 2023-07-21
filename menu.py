def pass_exception(*args, e, **kwargs):
	return False


class Menu:
	def __init__(self, text, options: dict, exit_state: str, handle_exception=None):
		if handle_exception is None:
			handle_exception = pass_exception
		self.text = text
		self.options = options
		self.exit_state = exit_state
		self.handle_exception = handle_exception

	def open(self, *args, **kwargs):
		print_menu = True
		state = ""
		
		while True:
			try:
				if print_menu:
					print(self.text)
					print_menu = False
				state = input()
				if state in self.options.keys():
					self.options[state](*args, **kwargs)
					print_menu = True
				elif state == self.exit_state:
					break
			except Exception as e:
				print_menu = True
				
				error_name = type(e).__name__
				if self.handle_exception(*args, e, **kwargs):
					try:
						self.options[state](*args, **kwargs)
					except Exception as e:
						print(f"{type(e).__name__}: {e}\n")
				else:
					print(f"{error_name}: {e}\n")
