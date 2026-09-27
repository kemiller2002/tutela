import threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from src.tutela_http_adapter import HttpPolicy, HttpPolicyError, make_http_adapter, origin

class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(401 if self.path=="/private" else 200)
  self.send_header("Set-Cookie","secret=never-record")
  self.end_headers(); self.wfile.write(b"bounded response")
 def log_message(self,*args): pass

class HttpAdapterTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.server=HTTPServer(("127.0.0.1",0),Handler)
  cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start()
  cls.base=f"http://127.0.0.1:{cls.server.server_port}"
 @classmethod
 def tearDownClass(cls): cls.server.shutdown(); cls.server.server_close()
 def test_refuses_non_authorized_origin(self):
  adapter=make_http_adapter(HttpPolicy((origin(self.base),)))
  with self.assertRaises(HttpPolicyError):
   adapter({"http":{"url":"http://example.invalid/"}},1)
 def test_negative_auth_probe_can_resist_and_redacts_cookie(self):
  adapter=make_http_adapter(HttpPolicy((origin(self.base),)))
  r=adapter({"http":{"url":self.base+"/private","method":"GET"},"expect":{"status":[401]}},1)
  self.assertEqual("RESISTED",r["outcome"]); self.assertEqual(401,r["status"])
  self.assertEqual("[REDACTED]",r["headers"]["Set-Cookie"])
 def test_unregistered_observation_is_indeterminate(self):
  adapter=make_http_adapter(HttpPolicy((origin(self.base),)))
  r=adapter({"http":{"url":self.base+"/","method":"GET"},"expect":{"status":[403]}},1)
  self.assertEqual("INDETERMINATE",r["outcome"])
 def test_violation_status_is_explicit(self):
  adapter=make_http_adapter(HttpPolicy((origin(self.base),)))
  r=adapter({"http":{"url":self.base+"/","method":"GET"},"expect":{"status":[403],"violationStatus":[200]}},1)
  self.assertEqual("VIOLATED",r["outcome"])

if __name__=="__main__": unittest.main()
