Oct. 15, 2026

**Summary**

The reported email is malicious credential phishing. It claims a Capital
One payment is on hold and tells the reader to open a
<span dir="rtl">“</span>secure attachment” to verify their account.
The body is copied from a genuine Capital One email, but the sender is
an unrelated address (winner@xserver\[.\]com) with no SPF, DKIM or
DMARC. The attached HTML file is a fake Capital One sign-in page that
sends the victim<span dir="rtl">’</span>s login, one-time codes,
personal details and card details to an outside server.

**Case Details**

<table>
<tbody>
<tr class="odd">
<td>Field</td>
<td>Value</td>
</tr>
<tr class="even">
<td>Playbook used</td>
<td>Phishing Email Triage</td>
</tr>
<tr class="odd">
<td>Source</td>
<td><p>Sample-1250</p>
<p><a href="https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-1250.eml"><span class="underline">https://github.com/rf-peixoto/phishing_pot/blob/main/email/sample-1250.eml</span></a></p></td>
</tr>
<tr class="even">
<td>Message ID</td>
<td><strong><a href="mailto:20230809011353.A4793969C16D077F@xserver.com"><span class="underline">20230809011353.A4793969C16D077F@xserver.com</span></a> (line17)</strong></td>
</tr>
<tr class="odd">
<td>Received by Proton Mail</td>
<td>09 Aug 2023 01:13:53 +0900</td>
</tr>
<tr class="even">
<td>Sent (Date header)</td>
<td></td>
</tr>
<tr class="odd">
<td>Receiving system</td>
<td>Proton Mail</td>
</tr>
<tr class="even">
<td>Subject</td>
<td>Action Required: New Payment Temporary on Hold</td>
</tr>
<tr class="odd">
<td>Tools used</td>
<td>Text editor, Message Header Analyzer, VirustTotal, Uriscan, Base64 decoder</td>
</tr>
</tbody>
</table>

**Findings**

|                                        |                                                                                                                                                                                                                                                                                                                                                                                                                          |                                                                                                                                        |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Check                                  | Result                                                                                                                                                                                                                                                                                                                                                                                                                   | Evidence (field, line)                                                                                                                 |
| Sender                                 | **winner@xserver\[ . \]com; Return-Path** is the same address                                                                                                                                                                                                                                                                                                                                                            | **Return-Path** (line 1), **Received** (line 4) **From** (line 13)                                                                     |
| Display name                           | Capita One (misspelled, missing the l in Capital)                                                                                                                                                                                                                                                                                                                                                                        | (Line 13)                                                                                                                              |
| SPF                                    | None                                                                                                                                                                                                                                                                                                                                                                                                                     | **Authentication-Results** (line 10)                                                                                                   |
| DKIM                                   | None                                                                                                                                                                                                                                                                                                                                                                                                                     | **Authentication-Results** (line 12)                                                                                                   |
| DMARC                                  | None                                                                                                                                                                                                                                                                                                                                                                                                                     | **Authentication-Results** (line 8)                                                                                                    |
| Source                                 | v133-18-212-99.vir.kagoya\[ . \]net 133\[ . \] 18\[ . \]212\[ . \]99                                                                                                                                                                                                                                                                                                                                                     | **Received** (Line 4)                                                                                                                  |
| Proton Mail spam score                 | 24                                                                                                                                                                                                                                                                                                                                                                                                                       | (line 55)                                                                                                                              |
| Content                                | attachment; filename="Secure\_Payment\_CapitalOne\_Accont.html"; name="Secure\_Payment\_CapitalOne\_Accont.html"                                                                                                                                                                                                                                                                                                         | (Line) 421                                                                                                                             |
| Links                                  | Point to real [<span class="underline">capitalone.com</span>](http://capitalone.com) domains, so the body is built to look real. The harm is in the attachment                                                                                                                                                                                                                                                           | Decoded body, lines 14, 57, 61, 68, 71, 74, 84                                                                                         |
| Other images                           | [<span class="underline">ecm.capitalone.com</span>](http://ecm.capitalone.com) logos and embedded cid: images                                                                                                                                                                                                                                                                                                            | Decoded body, lines 16, 58, 94, 99                                                                                                     |
| Tracking                               | 1x1 images exist, but they point to real [<span class="underline">capitalone.com</span>](http://capitalone.com) hosts, not attacker infrastructure                                                                                                                                                                                                                                                                       | Decoded body, lines 94, 99, 102                                                                                                        |
| Attachements                           | Secure\_Payment\_CapitalOne\_Accont.html: fake Capital One sign-in page with 6 forms and username, password and PIN fields. It loads scripts from bucolic-mandazi-68151a\[.\]netlify\[.\]app and posts what the victim types to jdlogisticscourier\[.\]com/wp-admin/images/tmp/[<span class="underline">capitalone.com/</span>](http://capitalone.com/) (data.php, otp1.php, otp2.php, mail.php, personal.php, card.php) | Content-Type (line 419), Content-Disposition (line 421), X-Attached (line 51); decoded attachment: \<form action="data.php"\>, $.post( |
| Body and attachment are base64-encoded |                                                                                                                                                                                                                                                                                                                                                                                                                          |                                                                                                                                        |

### 

**Indicators (defanged)**

|                   |                                                                                         |                                                     |
| ----------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------- |
| Type              | Value                                                                                   | Use                                                 |
| Sender domain     | **@xserver\[ . \]com**                                                                  | Block and search mail logs                          |
| Sender address    | **winner@xserver\[ . \]com**                                                            | Block and search mail logs                          |
| Sending server    | [v133-18-212-99\[ . \]vir\[ . \]kagoya\[ . \]net](http://v133-18-212-99.vir.kagoya.net) | Search mail logs; hosting IP, watch before blocking |
| Data Collection   | jdlogisticscourier\[.\]com                                                              | Block at proxy and DNS; search for visits           |
| Script host       | bucolic-mandazi-68151a\[.\]netlify\[.\]app                                              | Block at proxy and DNS; search for visits           |
| Attachment name   | Secure\_Payment\_CapitalOne\_Accont.html                                                | Search mail logs and block                          |
| Attachment SHA256 | **99edbec6dd4df95330ef8d0c14a5ff9a5b4ee066fbcdb1d5f57134398e8882f7**                    | Search mail and endpoint logs                       |
| Sending IP        | 133\[ . \]18\[ . \]212\[ . \]99                                                         |                                                     |

### 

**Response**

Search the mail system for other messages from winner@xserver\[.\]com,
with the attachment name or hash, or with links to the two domains
above.

Ask whether anyone opened the attachment or typed anything into the
page.

If nobody opened it: delete the message from mailboxes and block the
sender address, jdlogisticscourier\[.\]com and the netlify host. Block
the attachment hash if the tools allow.

If someone opened it and entered data: reset their password and revoke
sessions, check for the card or account details having been used, and
tell their bank or the card owner if card data was entered. Check proxy
or DNS logs for the visit and run an endpoint scan, with isolation
requested per company policy.

Escalate to Tier 2 if anyone opened the attachment and entered data, or
if the same message reached many recipients.

**Verdict**

Alert: reported email <span dir="rtl">“</span>Action Required: New
Payment Temporary on Hold”, 8 Aug 2023, from winner@xserver\[.\]com

What I checked: sender and display name, authentication, sending IP,
spam score, body text, links, images, attachment (decoded as text, never
opened)

Findings: no SPF, DKIM or DMARC. The body is a copy of a real Capital
One email with a <span dir="rtl">“</span>download the attachment” lure.
The attachment is a fake sign-in page that sends login, one-time code,
personal and card data to jdlogisticscourier\[.\]com.

Verdict: malicious, credential phishing. Reason: the attachment collects
credentials and card details and sends them to an unrelated server.

What would change it: nothing realistic. The data collection is in the
attachment<span dir="rtl">’</span>s code.

Not verified: reputation lookups for the hash,
jdlogisticscourier\[.\]com and the netlify host.
