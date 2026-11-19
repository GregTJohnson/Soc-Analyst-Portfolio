Nov 11, 2026

**Summary**

The reported email is malicious spam sent from a compromised NHS
mailbox, not a spoofed one. SPF, DKIM and DMARC passed because the
message really went through NHS mail servers, but a login from a rented
server sent it, and the subject ("Wallet Access Will Be Restricted") has
nothing to do with the body, a Chinese-language Mid-Autumn marketing
newsletter. Its one link goes through two click-tracking redirectors to
blackbot\[.\]tech/offer/. Credential phishing is not confirmed: the
email has no login request, no attachment, and the destination page was
not checked.

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
<td><p>Sample-6313</p>
<p><a href="https://github.com/rf-peixoto/phishing_pot/tree/main/email"><span class="underline">https://github.com/rf-peixoto/phishing_pot/tree/main/email</span></a></p></td>
</tr>
<tr class="even">
<td>Message ID</td>
<td><a href="mailto:20250106000404.95D0C39EDF764433@nhs.net"><strong><span class="underline">20250106000404.95D0C39EDF764433@nhs.net</span></strong></a></td>
</tr>
<tr class="odd">
<td>Received by Microsoft</td>
<td>5 Jan 2025 23:21:42 +0000</td>
</tr>
<tr class="even">
<td>Sent (Date header)</td>
<td>6 Jan 2025 00:04:05 +0100</td>
</tr>
<tr class="odd">
<td>Receiving system</td>
<td>Microsoft Outlook/Exchange Online</td>
</tr>
<tr class="even">
<td>Subject</td>
<td>Wallet Access Will Be Restricted on January 12, 2025</td>
</tr>
<tr class="odd">
<td>Tools used</td>
<td>Text editor, CyberChef, VirusTotal</td>
</tr>
</tbody>
</table>

**Findings**

|                      |                                                                                                                                                                                                                                             |                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Check                | Result                                                                                                                                                                                                                                      | Evidence (field, line)                                                          |
| From Line            | Malformed: display name "Kyc", address on-premisetest.user1205190@nhs\[.\]net, then a second address gp.g82152@nhs\[.\]net stuck on the end                                                                                                 | Line 56                                                                         |
| Sender identities    | Three different [<span class="underline">nhs.net</span>](http://nhs.net) mailboxes: From on-premisetest.user1205190, Return-Path gp.g82152, Reply-To sbs-s.payrolltransformationrequests                                                    | From (56), Reply-To (55), Return-Path (65)                                      |
| SPF, DKIM, DMARC     | All pass at Microsoft; DKIM signed by d=[<span class="underline">nhs.net</span>](http://nhs.net), aligned with the From domain. This shows the mail went through NHS servers, not that it is safe                                           | Authentication-Results (lines 14–17), Received-SPF (18), DKIM-Signature (29–30) |
| Earlier hop failure  | SPF and DMARC failed at the NHS mail server for the first hop (the submission relay), then passed at the next. Noted, not a missed finding                                                                                                  | Authentication-Results-Original (fail: 46, 48; pass: 26, 28)                    |
| Sending path         | Authenticated login (ESMTPSA) from customer-rental.rootlayer\[.\]net (private address 192.168.103.132) to send.nhs\[.\]net (20.49.136.120) at 23:04:05 UTC. Points to a compromised NHS account, not spoofing                               | Received (lines 52, 49)                                                         |
| Delivery path        | hsmail1.nhs\[.\]net (155.231.208.5) handed it to Microsoft at 23:21:39 UTC                                                                                                                                                                  | Received (line 21), Authentication-Results (line 14)                            |
| Read receipt         | Asks for a read receipt to ads@airarabia\[.\]com, an unrelated company                                                                                                                                                                      | Disposition-Notification-To (line 61)                                           |
| Microsoft spam score | 5                                                                                                                                                                                                                                           | X-MS-Exchange-Organization-SCL (line 85)                                        |
| Subject vs body      | Subject is a wallet / KYC deadline warning. Body is a Traditional Chinese Mid-Autumn marketing newsletter ("space adventure", bike rides, yoga, cocktail party) with no wallet text                                                         | Subject (line 58); decoded body (starts line 164)                               |
| Body source          | Images load from static.newsleopard\[.\]com, a marketing platform, so the body is a copied newsletter template                                                                                                                              | \<img src= (e.g. line 763)                                                      |
| Links                | One link wraps the whole body: xpohu.mjt\[.\]lu/lnk/… (a click-tracking redirector). Its last segment is base64 and decodes to click.pstmrk\[.\]it/3s/blackbot\[.\]tech/offer/… (a second redirector), pointing to blackbot\[.\]tech/offer/ | \<a href= (line 172)                                                            |
| Embedded image       | One image embedded as data:image/png;base64; not decoded                                                                                                                                                                                    | \<img src= (line 180)                                                           |
| Tracking             | No 1x1 pixel found. Tracking is the redirect link and the read receipt                                                                                                                                                                      | Decoded body; Disposition-Notification-To (line 61)                             |
| Attachements         | None. Only part is text/html, no multipart and no filename=                                                                                                                                                                                 | Content-Type (line 62)                                                          |

### 

**Indicators (defanged)**

|                      |                                                                             |                                                                                               |
| -------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Type                 | Value                                                                       | Use                                                                                           |
| Sender domain        | nhs\[ . \]net                                                               | Do not block: legitimate organization, account is compromised                                 |
| Sender address       | on-premisetest.user1205190@nhs\[ . \] net                                   | Block and search mail logs                                                                    |
| Sender address       | gp.g821252@nhs\[ . \]net                                                    | Block and search mail logs                                                                    |
| Reply To address     | Sbs-s.payrolltransormationrequests@nhs\[ . \]net                            | Block and search mail logs                                                                    |
| Destination domain   | Blackout\[ . \]tech                                                         | Block at proxy and DNS; search for visits                                                     |
| Redirector URLs      | xpohu.mjt\[.\]lu/lnk/… and click.pstmrk\[.\]it/3s/blackbot\[.\]tech/offer/… | Block the specific URLs and search logs; do not block the whole domains (legitimate services) |
| Read receipt address | ads@airarbia\[ . \]com                                                      | Watch only                                                                                    |
| Sending host         | customer-rental.rootlayer\[ . \]net                                         | Watch; not looked up                                                                          |
| Relay IP             | 20\[ . \]49\[ . \]136\[ . \]120                                             | Watch; not looked up                                                                          |
| Image host           | static.newsleopard\[ . \]com                                                | Do not block: marketing platform images only                                                  |

### 

**Response**

Search the mail system for other messages from the three nhs.net
addresses, or with links to blackbot\[.\]tech or the two redirector
paths.

Ask whether anyone clicked the link.

If nobody clicked: delete the message from mailboxes and block the three
sender addresses and blackbot\[.\]tech. Block the redirector URLs, not
their whole domains.

If someone clicked: ask what they did on the page (entered a password,
wallet details or payment data), check proxy or DNS logs for the visit,
reset credentials if any were entered, and run an endpoint scan as a
precaution.

Notify the NHS security or abuse contact that one of their mail accounts
appears compromised, through the channel company policy names.

Escalate to Tier 2 only if someone clicked and entered data, or the same
message reached many recipients.

**Verdict**

Alert: reported email "Wallet Access Will Be Restricted on January 12,
2025", sent 6 Jan 2025 00:04:05 +0100, from an nhs.net address.

What I checked: sender identities, authentication, sending path, read
receipt, spam score, subject against body, links, embedded and hidden
content, attachments.

Findings: the mail passed SPF, DKIM and DMARC because it was sent
through NHS servers, but by a login from a rented server. The From line
is malformed, three different nhs.net mailboxes appear, and the subject
does not match the body, a copied Chinese marketing newsletter. The only
link goes through two redirectors to blackbot\[.\]tech/offer/. No
attachment.

Verdict: malicious spam from a compromised NHS account. Reason:
authenticated login from an unrelated host, mismatched identities,
subject that does not match the body, and a double-redirected link.
Credential phishing is not confirmed because the email has no login
request.

What would change it: blackbot\[.\]tech/offer/ turning out to ask for a
login, wallet details or payment (it would become phishing), or turning
out to be a harmless promotion (it would become unwanted bulk mail).

**Not verified:** reputation of blackbot\[.\]tech, rootlayer\[.\]net and
20\[.\]49\[.\]136\[.\]120; the destination page's content; the embedded
data: image on line 180.
