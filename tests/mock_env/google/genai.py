class MockModels:
    def generate_content(self, *args, **kwargs):
        raise Exception("503 Service Unavailable")

class Client:
    def __init__(self, **kwargs):
        self.models = MockModels()
