#!/usr/bin/env python3
"""Local-first EML triage for email-security teams. Standard library only."""
from __future__ import annotations
import argparse, hashlib, html, json, re, sys
from dataclasses import asdict, dataclass
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

EXECUTABLE_EXTS={'.exe','.scr','.js','.jse','.vbs','.vbe','.bat','.cmd','.com','.ps1','.msi','.hta','.lnk','.iso','.img'}
ARCHIVE_EXTS={'.zip','.rar','.7z','.gz','.bz2','.xz'}
URL_RE=re.compile(r'https?://[^\s<>"\']+',re.I)

@dataclass
class Finding:
    severity:str; code:str; message:str; evidence:str=''

SEV={'critical':4,'high':3,'medium':2,'low':1,'info':0}

def auth_value(headers: list[str], key: str)->str:
    text=' '.join(headers).lower()
    m=re.search(rf'\b{re.escape(key)}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)',text)
    return m.group(1) if m else 'unknown'

def domains_from_text(text:str)->set[str]:
    out=set()
    for raw in URL_RE.findall(text):
        try:
            host=(urlsplit(raw.rstrip('.,);\'"')).hostname or '').lower().rstrip('.')
            if host: out.add(host)
        except ValueError: pass
    return out

def analyze_bytes(data:bytes, source='message.eml')->dict:
    msg=BytesParser(policy=policy.default).parsebytes(data)
    findings=[]
    auth_headers=msg.get_all('Authentication-Results',[]) + msg.get_all('ARC-Authentication-Results',[])
    auth={k:auth_value(auth_headers,k) for k in ('spf','dkim','dmarc')}
    for k,v in auth.items():
        if v in ('fail','softfail','permerror'): findings.append(Finding('high',f'{k.upper()}_FAIL',f'{k.upper()} authentication did not pass',v))
        elif v in ('none','unknown'): findings.append(Finding('medium',f'{k.upper()}_MISSING',f'{k.upper()} result is missing',v))
    from_name,from_addr=parseaddr(msg.get('From',''))
    reply_name,reply_addr=parseaddr(msg.get('Reply-To',''))
    if reply_addr and from_addr and reply_addr.lower()!=from_addr.lower():
        findings.append(Finding('medium','REPLY_TO_MISMATCH','Reply-To differs from From',f'{from_addr} -> {reply_addr}'))
    if from_name and '@' in from_name:
        findings.append(Finding('medium','DISPLAY_NAME_ADDRESS','Display name contains an email address',from_name))
    if any(ord(c)>127 for c in (from_addr or '').split('@')[0]):
        findings.append(Finding('medium','UNICODE_SENDER','Sender local-part contains non-ASCII characters',from_addr))
    urls=set(); attachments=[]; body_parts=[]
    for part in msg.walk():
        filename=part.get_filename()
        if filename:
            payload=part.get_payload(decode=True) or b''
            suffix=Path(filename).suffix.lower()
            attachments.append({'name':filename,'content_type':part.get_content_type(),'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest()})
            if suffix in EXECUTABLE_EXTS: findings.append(Finding('high','EXECUTABLE_ATTACHMENT','Executable or script attachment',filename))
            elif suffix in ARCHIVE_EXTS: findings.append(Finding('medium','ARCHIVE_ATTACHMENT','Archive attachment needs sandbox review',filename))
            if re.search(r'\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|bat|cmd)$',filename,re.I): findings.append(Finding('critical','DOUBLE_EXTENSION','Attachment uses a deceptive double extension',filename))
        elif part.get_content_type() in ('text/plain','text/html'):
            try: body_parts.append(part.get_content())
            except Exception: pass
    body='\n'.join(body_parts)
    urls=domains_from_text(body)
    for domain in sorted(urls):
        if domain.startswith('xn--') or '.xn--' in domain: findings.append(Finding('high','PUNYCODE_URL','URL contains an IDN punycode domain',domain))
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}',domain): findings.append(Finding('medium','IP_LITERAL_URL','URL uses a raw IP address',domain))
    received=len(msg.get_all('Received',[]))
    if received==0: findings.append(Finding('low','NO_RECEIVED','No Received headers found',''))
    findings.sort(key=lambda f:(-SEV[f.severity],f.code))
    score=min(100,sum({'critical':40,'high':25,'medium':10,'low':3,'info':0}[f.severity] for f in findings))
    return {'source':source,'sha256':hashlib.sha256(data).hexdigest(),'subject':str(msg.get('Subject','')),'from':from_addr,'reply_to':reply_addr,'message_id':str(msg.get('Message-ID','')),'auth':auth,'received_hops':received,'risk_score':score,'verdict':'high risk' if score>=50 else 'suspicious' if score>=20 else 'low risk','findings':[asdict(f) for f in findings],'urls':sorted(urls),'attachments':attachments}

def render_html(r:dict)->str:
    rows=''.join(f"<tr><td><span class='sev {html.escape(x['severity'])}'>{html.escape(x['severity'])}</span></td><td>{html.escape(x['code'])}</td><td>{html.escape(x['message'])}</td><td><code>{html.escape(x['evidence'])}</code></td></tr>" for x in r['findings']) or '<tr><td colspan=4>No findings</td></tr>'
    return f"""<!doctype html><meta charset=utf-8><title>Mail Threat Triage</title><style>body{{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#15202b}}h1{{margin-bottom:4px}}.score{{font-size:42px;font-weight:800}}.meta{{display:grid;grid-template-columns:140px 1fr;gap:7px;background:#f6f8fa;padding:18px;border-radius:12px}}table{{width:100%;border-collapse:collapse;margin-top:22px}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #ddd;vertical-align:top}}.sev{{padding:3px 7px;border-radius:10px;color:white}}.critical{{background:#7f1d1d}}.high{{background:#dc2626}}.medium{{background:#d97706}}.low{{background:#2563eb}}code{{overflow-wrap:anywhere}}small{{color:#667085}}</style><h1>Mail Threat Triage</h1><small>Local EML analysis. No message data leaves the machine.</small><p class=score>{r['risk_score']}/100</p><h2>{html.escape(r['verdict'].upper())}</h2><div class=meta><b>Subject</b><span>{html.escape(r['subject'])}</span><b>From</b><span>{html.escape(r['from'])}</span><b>SPF / DKIM / DMARC</b><span>{html.escape(r['auth']['spf'])} / {html.escape(r['auth']['dkim'])} / {html.escape(r['auth']['dmarc'])}</span><b>SHA-256</b><code>{r['sha256']}</code></div><table><thead><tr><th>Severity</th><th>Code</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>"""

def main():
    p=argparse.ArgumentParser(description='Analyze an .eml file without sending data anywhere')
    p.add_argument('eml',type=Path); p.add_argument('--format',choices=('json','html'),default='json'); p.add_argument('-o','--output',type=Path)
    a=p.parse_args(); r=analyze_bytes(a.eml.read_bytes(),a.eml.name); out=json.dumps(r,ensure_ascii=False,indent=2) if a.format=='json' else render_html(r)
    if a.output: a.output.write_text(out,encoding='utf-8')
    else: print(out)
    return 2 if r['risk_score']>=50 else 1 if r['risk_score']>=20 else 0
if __name__=='__main__': sys.exit(main())
