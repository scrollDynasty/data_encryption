import os
from concurrent.futures import ThreadPoolExecutor
from threading import Lock


class ChunkedFileHandler:
    def __init__(self, chunk_size=1024 * 1024):  # 1MB chunks
        self.chunk_size = chunk_size
        self.progress_lock = Lock()
        self.total_progress = 0

    def process_file(self, input_file, output_file, processor, max_workers=4, callback=None):
        file_size = os.path.getsize(input_file)
        chunks = self._split_file_into_chunks(file_size)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
                futures = []

                for chunk_start, chunk_size in chunks:
                    chunk_data = in_file.read(chunk_size)
                    future = executor.submit(processor, chunk_data)
                    futures.append((future, chunk_size))

                for future, chunk_size in futures:
                    processed_chunk = future.result()
                    out_file.write(processed_chunk)

                    with self.progress_lock:
                        self.total_progress += chunk_size
                        if callback:
                            progress = (self.total_progress / file_size) * 100
                            callback(int(progress))

    def _split_file_into_chunks(self, file_size):
        chunks = []
        position = 0
        while position < file_size:
            chunk_size = min(self.chunk_size, file_size - position)
            chunks.append((position, chunk_size))
            position += chunk_size
        return chunks