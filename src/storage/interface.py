# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/storage/interface.py
# DESCRIPTION: Abstract Base Class (Interface) for Storage Providers.
#              Defines the mandatory contract for SQLite, JSON, or ELK adapters.
#
# OPTIONS:
#
# PARAMETERS:
#
# AUTHOR: Mario Luz (Refactoring Sys-Inspector Project)
# CHANGELOG:
# VERSION: 0.50.56
# ==============================================================================

from abc import ABC, abstractmethod

class StorageProvider(ABC):
    """
    Abstract Interface for data persistence.
    Any storage backend (SQLite, JSON, Elastic) must implement these methods.
    """

    @abstractmethod
    def connect(self):
        """
        Establishes connection to the database or file system.
        Must handle connection errors gracefully.
        """
        pass

    @abstractmethod
    def save_snapshot(self, snapshot_data):
        """
        Persists a single system snapshot.

        Args:
            snapshot_data (dict): The complete dictionary containing OS,
                                  Hardware, and Process Tree data.
        Returns:
            bool: True if save was successful, False otherwise.
        """
        pass

    @abstractmethod
    def get_history(self, start_ts, end_ts):
        """
        Retrieves snapshots within a time range.

        Args:
            start_ts (float): Unix timestamp for the start of the range.
            end_ts (float): Unix timestamp for the end of the range.

        Returns:
            list: A list of snapshot dictionaries.
        """
        pass

    @abstractmethod
    def close(self):
        """
        Closes any open file handles or database connections.
        """
        pass
