from collections import deque


class FlowBuffer:
    """
    Temporary in-memory buffer for processed network flows.
    """

    def __init__(self, max_size=1000):
        self.buffer = deque(maxlen=max_size)

    def add_flow(self, flow):
        self.buffer.append(flow)

    def get_all(self):
        return list(self.buffer)

    def get_latest(self):
        if not self.buffer:
            return None

        return self.buffer[-1]

    def size(self):
        return len(self.buffer)

    def clear(self):
        self.buffer.clear()