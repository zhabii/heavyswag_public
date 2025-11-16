# from utils.verbose_mixin import VerboseMixin

class VerboseMixin:
    def verbose_print(self, msg:  str):
        if getattr(self, "is_verbose", False):
            print(msg)