import random
from typing import Tuple, List, Literal
import binascii # TODO: remove
import socket
from enum import Enum
import struct
from abc import ABC

VERSION = 3

class Op(Enum):
    SAVE = 100
    RESTORE = 200
    DELETE = 201
    LIST = 202

class Status(Enum):
    SUCCESS_RESTORE = 210
    SUCCESS_LIST = 211
    SUCCESS_SAVE = 212
    ERROR_NO_FILE = 1001
    ERROR_NO_CLIENT = 1002
    ERROR_GENERAL = 1003

# validations
    
def validate_range(var_name: str, number: int, uint_type: Literal["uint8_t", "uint16_t", "uint32_t", "uint64_t"]) -> None:
    ranges = {
        "uint8_t": (0, 0xFF),
        "uint16_t": (0, 0xFFFF),
        "uint32_t": (0, 0xFFFFFFFF),
        "uint64_t": (0, 0xFFFFFFFFFFFFFFFF)
    }

    min_val, max_val = ranges[uint_type]
    if not (min_val <= number <= max_val):
        raise ValueError(f"{var_name} {number} is out of range for {uint_type}.")

def validate_op(op: Op) -> None:
    if op not in Op:
        raise ValueError(f"Invalid op: {op.value}")
    
def validate_status(status: Status) -> None:
    if status not in Status:
        raise ValueError(f"Invalid status: {status}")

# common classes
    
class Filename:
    def __init__(self, filename: str):
        validate_range("name_len", len(filename), "uint16_t")
        self.name_len = len(filename)
        self.filename = filename

class Payload:
    def __init__(self, size: int, payload: bytes):
        validate_range("payload.size", size, "uint32_t")
        self.size = size
        self.payload = payload

# requests

class _RequestBase(ABC):
    def __init__(self, user_id: int, version: int, op: Op):
        validate_range("user_id", user_id, "uint32_t")
        validate_range("version", version, "uint8_t")
        validate_op(op)
        
        self.user_id = user_id
        self.version = version
        self.op = op.value

    def pack(self) -> bytes:
        return struct.pack(
            f'<I B B',
            self.user_id,
            self.version,
            self.op
        )

Request = _RequestBase

class _RequestWithFileName(_RequestBase):
    def __init__(self, user_id: int, version: int, op: Op, filename: str):
        super().__init__(user_id, version, op)
        self.filename = Filename(filename)
    
    def pack(self) -> bytes:
        return struct.pack(
            f'<I B B H {self.filename.name_len}s',
            self.user_id,
            self.version,
            self.op,
            self.filename.name_len,
            self.filename.filename.encode('utf-8')
        )

class RequestList(_RequestBase):
    def __init__(self, user_id: int, version: int):
        super().__init__(user_id, version, Op.LIST)

class RequestRestore(_RequestWithFileName):
    def __init__(self, user_id: int, version: int, filename: str):
        super().__init__(user_id, version, Op.RESTORE, filename)

class RequestDelete(_RequestWithFileName):
    def __init__(self, user_id: int, version: int, filename: str):
        super().__init__(user_id, version, Op.DELETE, filename)

class RequestSave(_RequestWithFileName):
    def __init__(self, user_id: int, version: int, filename: str, file_content: bytes):
        super().__init__(user_id, version, Op.SAVE, filename)
        self.payload = Payload(len(file_content), file_content)

    def pack(self) -> bytes:
        filename_bytes = self.filename.filename.encode('utf-8')
        return struct.pack(
            f'<I B B H {len(filename_bytes)}s I {len(self.payload.payload)}s',
            self.user_id,
            self.version,
            self.op,
            len(filename_bytes),
            filename_bytes,
            len(self.payload.payload),
            self.payload.payload
        )

# responses
    
class _ResponseBase(ABC):
    def __init__(self, version: int, status: Status):
        self.version = version
        self.status = status

    def __str__(self) -> str:
        return f"Version: {self.version}\nStatus: {self.status}"
        
Response = _ResponseBase

class ResponseErrorGeneral(_ResponseBase):
    def __init__(self, version: int):
        super().__init__(version, Status.ERROR_GENERAL)

class ResponseErrorNoClient(_ResponseBase):
    def __init__(self, version: int):
        super().__init__(version, Status.ERROR_NO_CLIENT)

class _ResponseWithFileName(_ResponseBase):
    def __init__(self, version: int, status: Status, filename: Filename):
        super().__init__(version, status)
        self.filename = filename
    
    def __str__(self) -> str:
        return super().__str__() + f"\nName length: {self.filename.name_len}\nFilename: {self.filename.filename}"

class ResponseSuccessSave(_ResponseWithFileName):
    def __init__(self, version: int, filename: Filename):
        super().__init__(version, Status.SUCCESS_SAVE, filename)

class ResponseErrorNoFile(_ResponseWithFileName):
    def __init__(self, version: int, filename: Filename):
        super().__init__(version, Status.ERROR_NO_FILE, filename)

class _ResponseWithFileNameAndPayload(_ResponseWithFileName):
    def __init__(self, version: int, status: Status, filename: Filename, payload: Payload):
        super().__init__(version, status, filename)
        self.payload = payload
    
    def __str__(self) -> str:
        return f"Version: {self.version}\nStatus: {self.status}\nName length: {self.filename.name_len}\nFilename: {self.filename.filename}\nPayload size: {self.payload.size}"

class ResponseSuccessRestore(_ResponseWithFileNameAndPayload):
    def __init__(self, version: int, filename: Filename, payload: Payload):
        super().__init__(version, Status.SUCCESS_RESTORE, filename, payload)

class ResponseSuccessList(_ResponseWithFileNameAndPayload):
    def __init__(self, version: int, filename: Filename, payload: Payload):
        super().__init__(version, Status.SUCCESS_LIST, filename, payload)

class FileHandler:
    SERVER_INFO_FILE = "server.info"
    BACKUP_INFO_FILE = "backup.info"
    def __init__(self):
        self.server_info_file = self.SERVER_INFO_FILE
        self.backup_info_file = self.BACKUP_INFO_FILE

    def validate_ip(self, ip: str) -> None:
        try:
            socket.inet_aton(ip)
        except socket.error:
            raise ValueError("Invalid IP address.")

    def validate_port(self, port: str) -> None:
        if not 0 <= int(port) <= 65535:
            raise ValueError("Invalid port number.")

    def read_server_info(self) -> Tuple[str, int]:
        try:
            with open(self.server_info_file, 'r') as file:
                ip_address, port = file.readline().strip().split(':')
                self.validate_ip(ip_address)
                self.validate_port(port)
                port = int(port)
        except FileNotFoundError:
            raise Exception(f"{self.server_info_file} file not found.")
        except Exception as e:
            raise Exception(f"An error occurred: {str(e)}")
        return ip_address, port

    def read_backup_info(self) -> List[str]:
        try:
            with open(self.backup_info_file, 'r') as file:
                filenames = [line.strip() for line in file]
        except FileNotFoundError:
            raise Exception(f"{self.backup_info_file} file not found.")
        except Exception as e:
            raise Exception(f"An error occurred: {str(e)}")
        return filenames

class UniqueIDGenerator:
    def __init__(self):
        self.generated_ids = set()

    def generate_unique_id(self) -> int:
        while True:
            unique_id = random.randint(0, 0xFFFFFFFF)
            if unique_id not in self.generated_ids:
                self.generated_ids.add(unique_id)
                return unique_id

class Client:
    def __init__(self, ip_address: str, port: int):
        self.ip_address = ip_address
        self.port = port

    def send_request(self, request: Request) -> None:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        my_socket.connect((self.ip_address, self.port))
        my_socket.send(request.pack())

        data = b""
        while True:
            part = my_socket.recv(1024)
            if not part:
                break 
            data += part

        response = self.unpack_response(data)
        print(response, '\n\n')

        my_socket.close()

    def unpack_response(self, data: bytes) -> Response:
        if len(data) < 3:
            raise Exception(f"Response too short; got {len(data)} bytes but expected at least 3")
        
        # Unpack the version and status
        version, status = struct.unpack('<B H', data[:3])
        status = Status(status)
        validate_range("version", version, "uint8_t")
        validate_status(status)

        if status == Status.ERROR_GENERAL:
            return ResponseErrorGeneral(version)
        elif status == Status.ERROR_NO_CLIENT:
            return ResponseErrorNoClient(version)
        
        if len(data) < 5:
            raise Exception(f"Response too short; got {len(data)} bytes but expected at least 5")
        
        # Unpack the name_len and filename
        name_len = struct.unpack('<H', data[3:5])[0]
        filename_start = 5
        filename_end = filename_start + name_len
        filename = data[filename_start:filename_end].decode('ascii')
        if len(filename) != name_len:
            raise ValueError(f"filename length ({len(filename)}) does not match name_len ({name_len}).")
        filename_obj = Filename(filename)

        if status == Status.SUCCESS_SAVE:
            return ResponseSuccessSave(version, filename_obj)
        elif status == Status.ERROR_NO_FILE:
            return ResponseErrorNoFile(version, filename_obj)
        
        if len(data) < filename_end + 4:
            raise Exception(f"Response too short; got {len(data)} bytes but expected at least {filename_end + 4}")

        # Unpack the payload
        payload_size = struct.unpack('<I', data[filename_end:filename_end+4])[0]
        payload_start = filename_end + 4
        payload_end = payload_start + payload_size
        payload = data[payload_start:payload_end]
        payload_obj = Payload(payload_size, payload)

        if status == Status.SUCCESS_RESTORE:
            return ResponseSuccessRestore(version, filename_obj, payload_obj)
        elif status == Status.SUCCESS_LIST:
            return ResponseSuccessList(version, filename_obj, payload_obj)
        
        raise Exception(f"Invalid status: {status}")

class RequestGenerator:
    def __init__(self, user_id):
        self.user_id = user_id

    def generate_save_request(self, filename: str) -> Request:
        with open(filename, "rb") as f:
            content = f.read()
        return RequestSave(self.user_id, VERSION, filename, content)

    def generate_restore_request(self, filename: str) -> Request:
        return RequestRestore(self.user_id, VERSION, filename)
    
    def generate_delete_request(self, filename: str) -> Request:
        return RequestDelete(self.user_id, VERSION, filename)

    def generate_list_request(self) -> Request:
        return RequestList(self.user_id, VERSION)

def main():
    uniqueIDGenerator = UniqueIDGenerator() 
    unique_id = uniqueIDGenerator.generate_unique_id() # step 1
    unique_id = 53764 # TODO: remove

    reader = FileHandler()
    ip_address, port = reader.read_server_info() # step 2
    filenames = reader.read_backup_info() # step 3
    # TODO: make sure len(filenames) >= 2

    client = Client(ip_address, port)

    generator = RequestGenerator(unique_id)
    client.send_request(generator.generate_list_request()) # step 4
    client.send_request(generator.generate_save_request(filenames[0])) # step 5
    client.send_request(generator.generate_save_request(filenames[1])) # step 6
    client.send_request(generator.generate_list_request()) # step 7
    client.send_request(generator.generate_restore_request(filenames[0])) # step 8, TODO: save on tmp
    client.send_request(generator.generate_delete_request(filenames[0])) # step 9
    client.send_request(generator.generate_restore_request(filenames[0])) # step 10

if __name__ == "__main__":
    main()