class NotAuthenticated(Exception):
    pass


class TechnitiumUnavailable(Exception):
    pass


class TechnitiumAPIError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class TechnitiumInvalidToken(Exception):
    pass
