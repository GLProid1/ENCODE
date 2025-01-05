import io
from pathlib import Path

def read_file_content(file, extension):
    """
    Reads file content based on file extension
    Returns bytes for all file types to ensure consistent encryption/decryption
    
    Args:
        file: FileStorage object from Flask
        extension: str, file extension including the dot
    
    Returns:
        bytes: File content as bytes
    """
    try:
        # Read the file content as bytes
        file_content = file.read()
        
        # For text files, we need to handle encoding
        if extension.lower() in ['.txt', '.csv']:
            # Try to decode and encode to handle text files consistently
            try:
                # Try to decode as UTF-8 first
                decoded_content = file_content.decode('utf-8')
                return decoded_content.encode('utf-8')
            except UnicodeDecodeError:
                # If UTF-8 fails, return the original bytes
                return file_content
        
        # For all other binary files (PDF, DOCX, XLS, etc.)
        # Return the raw bytes directly
        return file_content
        
    except Exception as e:
        raise ValueError(f"Failed to read {extension} file: {str(e)}")

def write_file_content(content, filename):
    """
    Prepares file content for download
    
    Args:
        content: bytes, the file content
        filename: str, the output filename
    
    Returns:
        BytesIO: File content ready for download
    """
    output = io.BytesIO()
    output.write(content)
    output.seek(0)
    return output