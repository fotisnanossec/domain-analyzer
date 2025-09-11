class ToolNotFoundError(Exception):
    """Exception raised when a required external tool is not found."""
    pass

class SubprocessFailedError(Exception):
    """Exception raised when a subprocess command fails to execute successfully."""
    pass

class ReportGenerationError(Exception):
    """Exception raised when the report generation process fails."""
    pass
