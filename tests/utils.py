import json
from stix2.serialization import serialize

def stix_as_dict(stix_obj):
    return json.loads(serialize(stix_obj))

    
class FakeResponse:
    def __init__(self, content=b"", status_code=200):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="ignore")
        self.ok = status_code < 400

    def json(self):
        return json.loads(self.text)
    
    def raise_for_status(self):
        if not self.ok:
            raise Exception(f"HTTP {self.status_code}")
    
class FakeJSONResponse(FakeResponse):
    def __init__(self, response, status_code=200):
        content = json.dumps(response).encode("utf-8")
        super().__init__(content, status_code)