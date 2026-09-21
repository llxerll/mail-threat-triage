import unittest
from mail_triage import analyze_bytes, domains_from_text
class TriageTests(unittest.TestCase):
 def test_clean_auth(self):
  r=analyze_bytes(b'From: Alice <alice@example.com>\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nReceived: by mx\nSubject: hi\n\nhello')
  self.assertEqual(r['risk_score'],0); self.assertEqual(r['auth']['dmarc'],'pass')
 def test_mismatch_and_attachment(self):
  raw=b'From: CEO <ceo@example.com>\nReply-To: pay@evil.test\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\nMIME-Version: 1.0\nContent-Type: application/octet-stream; name="invoice.pdf.exe"\nContent-Disposition: attachment; filename="invoice.pdf.exe"\nContent-Transfer-Encoding: base64\n\nWA=='
  r=analyze_bytes(raw)
  codes={x['code'] for x in r['findings']}
  self.assertIn('DOUBLE_EXTENSION',codes); self.assertIn('REPLY_TO_MISMATCH',codes); self.assertEqual(r['verdict'],'높은 위험')
 def test_urls(self): self.assertEqual(domains_from_text('go https://example.com/a and http://1.2.3.4/x'),{'example.com','1.2.3.4'})
if __name__=='__main__': unittest.main()
