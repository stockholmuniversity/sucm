from abc import ABC, abstractmethod


class SucmSecret(ABC):
    @abstractmethod
    def get_all_paths(self):
        pass

    def read_secret(self, file_name):
        pass

    def modify_or_create_secret(self, file_name, file_data):
        pass

    def remove_secret(self, file_name):
        pass
