from abc import ABC, abstractmethod


class SucmSecret(ABC):
    @abstractmethod
    def get_all_paths(self):
        """
        Returns a list of paths
        """
        pass

    def read_secret(self, file_name):
        """
        returns file in bytecode
        """
        pass

    def modify_or_create_secret(self, file_name, file_data):
        """
        rotates the files in the storage system (vault or whatever)
        """
        pass

    def remove_secret(self, file_name):
        """
        removes the secret from the storage system
        """
        pass
